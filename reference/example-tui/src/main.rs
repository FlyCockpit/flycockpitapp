fn main() -> std::process::ExitCode {
    match excoc::main_entry() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("excoc: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
