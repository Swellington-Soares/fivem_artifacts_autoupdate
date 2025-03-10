This program automatically downloads FiveM artifacts (if necessary) and starts the server. It is recommended to use it only in a development environment.

how to use:

fivem-update.exe --exec path_to_cfg_file

Also pass the disable-auto-update argument if you do not want to check if the artifact is up to date. (The artifacts will be downloaded anyway if the program does not find them).

how to build:

1. Download and install the latest rust compiler from https://rustup.rs/
2. Download the source code (this repository)
3. Open repository folder in terminal
4. Run cargo build --release


if you see an error, open a issue and I will try to help you.