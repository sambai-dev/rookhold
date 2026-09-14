#[cfg(target_os = "linux")]
fn main() {
    // This binary is intentionally tiny and synchronous. The server launches
    // it as a fresh process so namespace setup and the PID1 fork never occur
    // inside Tokio's multithreaded runtime.
    std::process::exit(coop_exec::linux_sandbox::helper_main());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("{} is available only on Linux", env!("CARGO_BIN_NAME"));
    std::process::exit(64);
}
