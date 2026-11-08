#[cfg(windows)]
fn main() {
    eprintln!("native implementation pending");
    std::process::exit(1);
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows-only read-only identity evidence tool");
    std::process::exit(1);
}
