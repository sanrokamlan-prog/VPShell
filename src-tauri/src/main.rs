// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::var("VPSHELL_SSH_ASKPASS").as_deref() == Ok("1") {
        let prompt = std::env::args().nth(1);
        std::process::exit(vpshell_lib::run_ssh_askpass(prompt.as_deref()));
    }
    vpshell_lib::run()
}
