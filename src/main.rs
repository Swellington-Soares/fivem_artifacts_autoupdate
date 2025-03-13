use clap::{Arg, Command};
use clap_help::Printer;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::Client;
use rust_i18n::{i18n, set_locale, t};
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;
use std::cmp::min;
use std::env;
use std::fs::{remove_dir_all, File};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use sys_locale::get_locale;
use tokio;
use tokio::task::spawn_blocking;
use zip::read::ZipArchive;

const FIVEM_FXSERVER_LINK: &str =
    "https://changelogs-live.fivem.net/api/changelog/versions/win32/server";

i18n!("locales", fallback = "en");

#[derive(Debug, Deserialize)]
struct FxServerVersion {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    latest: u32,
    latest_download: String,
}

async fn get_fx_online_version() -> Option<(String, u32)> {
    match reqwest::get(FIVEM_FXSERVER_LINK).await {
        Ok(response) => match response.json::<FxServerVersion>().await {
            Ok(body) => Some((body.latest_download, body.latest)),
            Err(_) => None,
        },
        Err(_) => None,
    }
}

fn find_resources_directory(file_path: &str) -> Option<PathBuf> {
    println!("{}", file_path);
    let mut __current_path = PathBuf::from(file_path);
    let mut current_path = env::current_dir()
        .unwrap()
        .join(__current_path)
        .to_path_buf();
    if !current_path.pop() {
        return None;
    }
    loop {
        let resources_path = current_path.join("resources");
        if resources_path.exists() && resources_path.is_dir() {
            return Some(current_path);
        }
        if !current_path.pop() {
            break;
        }
    }
    None
}

fn get_fxserver_version(fxpath: &str) -> u32 {
    let output = std::process::Command::new(fxpath)
        .arg("--version")
        .output()
        .expect(&t!("error.failed_to_open_fxserver"));

    let output_str = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"v\d+\.\d+\.\d+\.(\d+)").unwrap();
    if let Some(captures) = re.captures(output_str.trim()) {
        if let Some(version) = captures.get(1) {
            return version.as_str().parse::<u32>().unwrap();
        }
    }
    return 0;
}

fn check_fx_local_version(path: &PathBuf) {
    println!("{}", t!("info.verify_fx_local_version"));
    let fxserver_path = path
        .join("artifacts/fxserver.exe")
        .canonicalize()
        .expect(&t!("error.failed_to_get_canonical_path"));

    if let Some(fxserver_str) = fxserver_path.to_str() {
        let fxserver_version = get_fxserver_version(fxserver_str);
        println!("{}", t!("info.current_version", value = fxserver_version));
        println!();
        std::process::exit(0);
    } else {
        println!("{}", t!("error.failed_to_get_canonical_path"));
        std::process::exit(0);
    }
}

async fn check_fx_online_version() {
    println!("{}", t!("info.verify_fx_online_version"));
    get_fx_online_version().await.map(|(_, version)| {
        println!("{}", t!("info.latest_version", value = version));
        println!();
    });
    std::process::exit(0);
}

async fn download_file(url: &str, output_path: &str) -> Result<(), String> {
    let client = Client::new();
    // Reqwest setup
    let res = client
        .get(url)
        .send()
        .await
        .map_err(|_| format!("Failed to GET from '{}'", &url))?;

    let total_size = res.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));
    pb.set_message(&format!("Baixando {}", url));

    // Download chunks
    let mut file = File::create(output_path)
        .map_err(|_| format!("{}", t!("erro.failed_to_create_temp_file").to_string()))?;
    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|_| t!("error.download_internal_failed").to_string())?;
        file.write_all(&chunk)
            .map_err(|_| t!("error.write_file_error").to_string())?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    pb.finish();

    Ok(())
}

async fn extract_file(inputfilename: &str, output_path: &PathBuf) -> Result<(), String> {
    println!("{}", t!("info.extracting_fxserver"));

    let fxserverfile = inputfilename.to_string();
    let extract_path = output_path.clone();

    if output_path.exists() {
        remove_dir_all(&output_path).expect(&t!("error.failed_to_access_file"));
    }

    let result = spawn_blocking(move || {
        let file = File::open(&fxserverfile)
            .map_err(|_| format!("{}", t!("error.write_file_error").to_string()))?;

        let mut archive = ZipArchive::new(BufReader::new(file))
            .map_err(|_| format!("{}", t!("error.write_file_error").to_string()))?;

        let total_files = archive.len() as u64;
        let pb = ProgressBar::new(total_files);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("🗂️  {wide_bar} {pos}/{len} - ({eta})")
                .progress_chars("█▇▆▅▄▃▂▁ "),
        );

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|_| format!("{}", t!("error.failed_to_access_file").to_string()))?;

            let outpath = extract_path.join(file.mangled_name());

            if file.is_dir() {
                std::fs::create_dir_all(&outpath)
                    .map_err(|_| format!("{}", t!("error.failed_to_access_file").to_string()))?;
            } else {
                if let Some(parent) = outpath.parent() {
                    std::fs::create_dir_all(parent).map_err(|_| {
                        format!("{}", t!("error.failed_to_access_file").to_string())
                    })?;
                }

                let mut outfile = File::create(&outpath)
                    .map_err(|_| format!("{}", t!("error.failed_to_access_file").to_string()))?;

                io::copy(&mut file, &mut outfile)
                    .map_err(|_| format!("{}", t!("error.failed_to_access_file").to_string()))?;
            }

            pb.inc(1);
        }

        pb.finish_with_message(&t!("info.extract_finalized"));
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| format!("{}", t!("error.failed_to_extract_file").to_string()))?;

    result
}

async fn download_fxserver_and_extract(artifacts_path: &PathBuf) -> Result<(), String> {
    let (link, _) = get_fx_online_version()
        .await
        .ok_or(t!("error.failed_to_get_latest_version").to_string())?;
    println!("{}", t!("info.downloading_fxserver"));
    let temp_dir = tempfile::tempdir().expect(&t!("error.failed_to_create_temp_dir"));
    let temp_dir_path = temp_dir.path();
    let temp_dir_path_str = temp_dir_path.to_str().unwrap();
    match Path::new(temp_dir_path_str).join("_fxserver.zip").to_str() {
        Some(path_str) => match download_file(&link, path_str).await {
            Ok(_) => {
                println!("{}", t!("info.fxserver_updated"));
                extract_file(path_str, artifacts_path).await?;
            }
            Err(err) => {
                return Err(format!(
                    "{}",
                    t!("error.failed_to_download_fxserver", value = err)
                ));
            }
        },
        None => {
            return Err(format!("{}", t!("error.failed_to_write_file_to_disk")));
        }
    }

    Ok(())
}

fn start_fxserver(fxpath: &PathBuf, workdir: &PathBuf, fxconfig: &PathBuf, args: &str) {
    println!("{}", t!("info.starting_fxserver"));
    let cmd = std::process::Command::new(fxpath.to_str().unwrap())
        .current_dir(workdir)
        .arg("+exec")
        .arg(fxconfig.to_str().unwrap())
        .arg(args.replace("\"", ""))
        .spawn();

    cmd.expect(&t!("error.failed_to_start_fxserver"));
}

#[tokio::main]
async fn main() {
    let server_resources_directory: PathBuf;
    let server_config_filepath: PathBuf;
    let mut enabled_auto_update = true;

    set_locale(&get_locale().unwrap_or_else(|| String::from("en")));
    let cmd = Command::new("fivem-update.exe")
        .version("1.0")
        .author("Swellington Soares")
        .arg(
            Arg::new("exec")
                .short('e')
                .long("exec")
                .help(t!("cli.exec_help").to_string()),
        )
        .arg(
            Arg::new("fx")
                .long("fx")
                .help(t!("cli.fx_help").to_string()),
        )
        .subcommand(
            Command::new("disable-auto-update")
                .about(t!("cli.disable_auto_update_help").to_string()),
        )
        .subcommand(Command::new("fx-version").about(t!("cli.verify_version_help").to_string()))
        .subcommand(Command::new("check-version").about(t!("cli.check_version_help").to_string()));

    let args = cmd.clone().get_matches();

    if !args.args_present() && args.subcommand().is_none() {
        let _ = Printer::new(cmd).print_help();
        std::process::exit(0);
    }

    let default_exec = "config.cfg".to_string();
    let exec = args.get_one::<String>("exec").unwrap_or(&default_exec);

    let server_config_path = Path::new(exec);

    if !server_config_path.exists() {
        println!("{}", t!("error.no_server_cfg_path"));
        std::process::exit(0);
    }

    server_config_filepath = server_config_path.to_path_buf();

    if let Some(resources_directory) = find_resources_directory(exec) {
        server_resources_directory = resources_directory;
    } else {
        println!("{}", t!("error.no_resources_directory"));
        std::process::exit(0);
    }

    match args.subcommand() {
        Some(("disable-auto-update", _)) => {
            enabled_auto_update = false;
        }
        Some(("fx-version", _)) => {
            check_fx_local_version(&server_resources_directory);
        }
        Some(("check-version", _)) => {
            check_fx_online_version().await;
        }
        _ => {}
    }

    let default_fx_args = "".to_string();
    let fx_arg = args
        .get_one::<String>("fx")
        .unwrap_or_else(|| &default_fx_args);

    println!("{}", t!("info.staring_process"));

    if !enabled_auto_update {
        println!("{}", t!("info.auto_update_disabled"));
        println!();
    }

    let artifacts_path = server_resources_directory.join("artifacts");
    let fxserver_path = artifacts_path.join("fxserver.exe");

    if !fxserver_path.exists() {
        println!("{}", t!("error.fxserver_not_found"));
        println!("{}", t!("info.trying_to_download_latest_version"));
        match download_fxserver_and_extract(&artifacts_path).await {
            Ok(_) => {
                start_fxserver(
                    &fxserver_path,
                    &server_resources_directory,
                    &server_config_filepath,
                    &fx_arg,
                );
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    } else {
        if enabled_auto_update {
            println!("{}", t!("info.verify_fx_local_version"));
            match get_fx_online_version().await {
                Some((_, version)) => {
                    let fxpath = fxserver_path.canonicalize().expect("");
                    let current_version = get_fxserver_version(fxpath.to_str().unwrap());
                    if current_version < version {
                        println!("{}", t!("info.available_version_folder", value = version));
                        println!("{}", t!("info.current_version", value = current_version));

                        match download_fxserver_and_extract(&artifacts_path).await {
                            Ok(_) => {
                                println!("{}", t!("info.fxserver_updated"));
                            }
                            Err(e) => {
                                println!("{}", e);
                            }
                        }
                    } else {
                        println!("{}", t!("info.fxserver_updated"));
                    }
                }
                None => {
                    println!("{}", t!("error.failed_to_get_latest_version"));
                }
            }
        }
        start_fxserver(
            &fxserver_path,
            &server_resources_directory,
            &server_config_filepath,
            &fx_arg,
        );
    }
}
