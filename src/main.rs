/*
 * Copyright (C) 2025 Swellington Soares.
 *
 * Este código é fornecido "como está", sem garantias de qualquer tipo.
 *
 * Restrição de uso:
 * - O uso comercial deste código não é permitido sem autorização prévia.
 * - Modificações e redistribuições devem manter este aviso de licença.
 * - O código pode ser usado para fins pessoais e educacionais.
 *
 * Para mais informações, consulte os termos em <URL ou contato>.
 */

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::fs::{self, read_to_string, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use regex::Regex;
use scraper::{Html, Selector};
use std::env;
use tokio;
use tokio::task::spawn_blocking;
use std::cmp::min;
use futures_util::StreamExt;

const FIVEM_FXSERVER_LINK: &str = "https://runtime.fivem.net/artifacts/fivem/build_server_windows/master/";


async fn download_file(url: &str, path: &str) -> Result<(), String> {
    let client = Client::new();
    // Reqwest setup
    let res = client
        .get(url)
        .send()
        .await
        .map_err(|_| format!("Failed to GET from '{}'", &url))?;

    let total_size = res.content_length().unwrap_or(0);
    //.ok_or(format!("Failed to get content length from '{}'", &url))?;

    // Indicatif setup
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));
    pb.set_message(&format!("Downloading {}", url));

    // Download chunks
    let mut file = File::create(path).map_err(|_| format!("Failed to create file '{}'", path))?;
    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|_| "Error while downloading file")?;
        file.write_all(&chunk)
            .map_err(|_| "Error while writing to file")?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    pb.finish();
    Ok(())
}

fn parser_link_and_version(html: &str) -> Option<(String, u32)> {
    // Parseia o HTML
    let document = Html::parse_document(html);

    // Define o seletor para a classe 'is-active'
    let selector = Selector::parse("a.is-active").unwrap();

    // Encontra o link que corresponde ao seletor
    if let Some(element) = document.select(&selector).next() {
        // Extrai o link do atributo href
        if let Some(mut href) = element.value().attr("href") {
            // Remove o ponto (.) antes da barra (/)
            if href.starts_with("./") {
                href = &href[1..]; // Remove os dois primeiros caracteres
            }

            // Usa regex para extrair o número (versão) da URL
            let re = Regex::new(r"/(\d+)-").unwrap();
            if let Some(captures) = re.captures(href) {
                let version_str = captures.get(1).map_or("", |m| m.as_str());

                if let Ok(version) = version_str.parse::<u32>() {
                    return Some((href.to_string(), version));
                }
            }
        }
    }

    None
}


async fn get_fxserver_online_info() -> Option<(String, u32)> {
    let temp_dir = tempfile::tempdir().expect("❌ Não foi possível criar o diretório temporário.");
    let temp_dir_path = temp_dir.path();
    let temp_dir_path_str = temp_dir_path.to_str().unwrap(); 
    match Path::new(temp_dir_path_str).join("sv.html").to_str() {
        Some(path_str) => {
            download_file(&FIVEM_FXSERVER_LINK, path_str).await.unwrap();
            let html_content = read_to_string(path_str).expect("❌ Não foi possível ler o arquivo de informação.");
            let (link, version) = parser_link_and_version(&html_content)
                .expect("❌ Não foi possível encontrar o link e a versão.");
            Some((link, version))
        }
        None => {            
            None
        }        
    }
}

fn find_resources_directory(file_path: &str) -> Option<PathBuf> {   
    let mut __current_path = PathBuf::from(file_path);
    let mut current_path = env::current_dir().unwrap().join(__current_path).to_path_buf();   
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

async fn extract_file(fxserverfile: &str, server_cfg_filename: &str) -> Result<(), String> {
    println!("✔️  Extraindo FxServer...");

    let diretorio = find_resources_directory(server_cfg_filename)
        .ok_or_else(|| "❌ Não foi possível encontrar o diretório 'resources'.".to_string())?;

    if !diretorio.is_dir() {
        return Err(format!("❌ O diretório '{}' não é válido.", diretorio.display()));
    }


    let extract_path = diretorio.join("artifacts");

    let fxserverfile = fxserverfile.to_string();
    let extract_path = extract_path.clone();

    spawn_blocking(move || {
        sevenz_rust::decompress_file(&fxserverfile, &extract_path)
    })
    .await
    .map_err(|err| format!("❌ Erro ao executar a descompressão: {err}"))?
    .map_err(|err| format!("❌ Erro ao extrair o arquivo: {err}"))?;

    Ok(())
}

async fn download_fxserver_and_extract(cfg_path: &str) -> Result<(), String> {
    let (link, version) = get_fxserver_online_info().await.ok_or("❌ Falha ao obter informações do FxServer.")?;
    println!("✨  Baixando FxServer...");
    println!("✔️  Versão: {}", version);
    let temp_dir = tempfile::tempdir().expect("❌ Failed to download FxServer file");
    let temp_dir_path = temp_dir.path();
    let temp_dir_path_str = temp_dir_path.to_str().unwrap(); 
    match Path::new(temp_dir_path_str).join("_fxserver.7z").to_str() {
        Some(path_str) => {            
            match download_file(&format!("{}{}", FIVEM_FXSERVER_LINK, link), path_str).await {
                Ok(_) => {
                    println!("✅  FxServer baixado com sucesso.");                   
                    extract_file(path_str, cfg_path).await?;                  
                    println!("✅  FxServer extraído com sucesso.");
                }
                Err(err) => {
                    return Err(format!("❌ Erro ao baixar o FxServer: {err}"));
                }
            }
        }
        None => {           
            return Err("❌ Erro ao converter o caminho para string.".to_string());
        }        
    }
    
    Ok(())
}

//CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, help = "Caminho do arquivo de configuração do servidor.", default_value_t = String::from("server.cfg"))]
    exec: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    #[command(about = "Desabilita a atualização automática dos artefatos.")]
    DisableAutoUpdate,
}

fn start_server(fxpath: &str, arg: &str) {
    println!("⚙️  Iniciando servidor...");
    let mut command = Command::new(fxpath);
    command.arg("+exec");
    command.arg(arg);
    command.spawn().expect("❌  Erro ao iniciar o servidor.");
}

fn get_fxserver_current_version(fxpath: &str) -> u32 {
    let output = Command::new(fxpath)
        .arg("--version")
        .output()
        .expect("❌  Erro ao executar o comando");

    let output_str = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"v\d+\.\d+\.\d+\.(\d+)").unwrap();
    if let Some(captures) = re.captures(output_str.trim()) {
        if let Some(version) = captures.get(1) {            
            return version.as_str().parse::<u32>().unwrap();
        }
    }
    return 0;
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut enable_update = true;
    match cli.command {
        Some(Commands::DisableAutoUpdate) => {
            enable_update = false;
            println!("ℹ️  Atualizações automáticas foram desativadas.");
        }
        None => {}
    }

    println!("⚙️  Verificando sistema...");

    // Verifica se o arquivo de configuração existe
    if !std::path::Path::new(&cli.exec).exists() {
        println!("❌  Servidor não encontrado no diretório atual.");
        println!("✅  Especifique o caminho para o servidor na linha de comando.");
        println!("✅  Use fivem-update.exe --exec <caminho_para_o_servidor>");
        return;
    }

    println!("⚙️  Verificando FxServer...");

    match find_resources_directory(&cli.exec) {
        Some(resources_dir) => {
            println!("✅  Encontrado diretório de recursos: {}", resources_dir.display());
            //verifica se o FxServer.exe existe
            if !Path::new(&resources_dir.join("artifacts/FxServer.exe")).exists() {
                println!("❌  FxServer não encontrado.");
                println!("⏱️  Baixando FxServer...");               
                match download_fxserver_and_extract(&cli.exec).await {
                    Ok(_) => {                        
                        let fxpath = resources_dir.join("artifacts/FxServer.exe").canonicalize().unwrap();
                        let fxpath_str = fxpath.to_str().unwrap();
                        start_server(fxpath_str, &cli.exec);
                    }
                    Err(err) => {
                        println!("❌ Erro ao extrair o arquivo: {}", err);
                    }                    
                }
            } else {
                let fxpath = resources_dir.join("artifacts/FxServer.exe").canonicalize().unwrap();
                let fxpath_str = fxpath.to_str().unwrap();

                if enable_update {
                    println!("⏱️  Verificando atualizações...");
                    let current_version = get_fxserver_current_version(&fxpath_str);
                    let (_, latest_version) = get_fxserver_online_info().await.unwrap();
                    if current_version < latest_version {
                        println!("ℹ️  Atualização disponível.");
                        println!("ℹ️  Versão Atual: {}", current_version);
                        println!("ℹ️  Versão Disponponível: {}", latest_version);
                        println!("⏱️  Baixando atualização...");
                        fs::remove_dir_all(&resources_dir.join("artifacts")).expect("Erro ao remover o diretório de recursos.");
                        match download_fxserver_and_extract(&cli.exec).await {
                            Ok(_) => {                        
                                let fxpath = resources_dir.join("artifacts/FxServer.exe").canonicalize().unwrap();
                                let fxpath_str = fxpath.to_str().unwrap();
                                start_server(fxpath_str, &cli.exec);
                            }
                            Err(err) => {
                                println!("❌ Erro ao extrair o arquivo: {}", err);
                            }                    
                        }                      
                    } else {
                        println!("✅  Não há atualizações disponíveis.");
                        start_server(fxpath_str, &cli.exec);                        
                    }                    
                } else {                                
                    start_server(fxpath_str, &cli.exec);
                }
            }
        }
        None => {
            println!("❌ Diretório [ resources ] não encontrado, finalizando.");
            return;
        }        
    }
}