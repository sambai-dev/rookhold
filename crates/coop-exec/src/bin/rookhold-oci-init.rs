#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(coop_exec::oci_init::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("{} is available only on Linux", env!("CARGO_BIN_NAME"));
    std::process::exit(64);
}
