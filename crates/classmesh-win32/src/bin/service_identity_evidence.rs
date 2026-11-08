#[cfg(windows)]
fn main() {
    use classmesh_win32::service_identity_evidence::native;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!(
            "Read-only reviewer evidence. --self-audit | --observe-existing-service\nRequires an unchanged ordinary caller for target access; no Service installation, token switching or authentication. Run in an externally bounded child process."
        );
        return;
    }
    let value = if args.as_slice() == ["--self-audit"] {
        native::audit_current_caller().map(|audit| serde_json::json!({"schema":1,"audit_only":true,"authenticated_service_worker":false,"caller":audit}))
    } else if args.as_slice() == ["--observe-existing-service"] {
        Ok(
            serde_json::to_value(native::measure_current_context())
                .expect("serialize fixed report"),
        )
    } else {
        eprintln!("Expected exactly --self-audit, --observe-existing-service or --help");
        std::process::exit(2);
    };
    match value.and_then(|v| serde_json::to_string(&v).map_err(std::io::Error::other)) {
        Ok(json) if json.len() <= 16384 => println!("{json}"),
        _ => {
            eprintln!("Native audit failed or report exceeded bound; no qualifying measurement");
            std::process::exit(1);
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows-only read-only identity evidence tool");
    std::process::exit(1);
}
