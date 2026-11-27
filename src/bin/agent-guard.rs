fn main() -> std::process::ExitCode {
    match agent_guard::cli::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("guard: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
