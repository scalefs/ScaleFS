
use scalefs_daemon::service;
use scalefs_ipc::endpoint::Endpoint;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

const USAGE: &str = "usage: scalefsd serve [--endpoint <name-or-path>] \
                     [--state-dir <dir>] [--trust-enforce]\n\
                     |      scalefsd service <install|uninstall|run> \
                     [--endpoint <name-or-path>] [--state-dir <dir>]\n\
                     |      scalefsd version";

fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("serve") => match parse_serve(&args[1..]) {
            Ok(parsed) => {
                #[cfg(unix)]
                service::arm_termination_signals(&parsed.endpoint);
                #[cfg(windows)]
                service::arm_console_handler(&parsed.endpoint);
                let mut options = scalefs_daemon::ServeOptions::new(&parsed.endpoint);
                options.state_dir = parsed.state_dir;
                options.trust_enforce = parsed.trust_enforce;
                match scalefs_daemon::serve_with(options) {
                    Ok(()) => 0,
                    Err(message) => {
                        eprintln!("scalefsd: {message}");
                        1
                    }
                }
            }
            Err(message) => {
                eprintln!("scalefsd: {message}");
                2
            }
        },
        Some("service") => match parse_service(&args[1..]) {
            Ok(ServiceCommand::Install(options)) => report(service::install(&options)),
            Ok(ServiceCommand::Uninstall) => report(service::uninstall()),
            Ok(ServiceCommand::Run(options)) => report(service::run(options)),
            Err(message) => {
                eprintln!("scalefsd: {message}");
                2
            }
        },
        Some("version") => {
            println!(
                "scalefsd {} (protocol {}, on-disk format v{})",
                env!("CARGO_PKG_VERSION"),
                scalefs_ipc::proto::PROTOCOL_VERSION,
                scalefs_core::FORMAT_VERSION,
            );
            0
        }
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

fn report(outcome: Result<(), String>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("scalefsd: {message}");
            1
        }
    }
}

struct ServeArgs {
    endpoint: Endpoint,
    state_dir: Option<std::path::PathBuf>,
    trust_enforce: bool,
}

fn parse_serve(args: &[String]) -> Result<ServeArgs, String> {
    let mut parsed = ServeArgs {
        endpoint: Endpoint::default_endpoint(),
        state_dir: None,
        trust_enforce: false,
    };
    let mut rest = args;
    while let Some((flag, tail)) = rest.split_first() {
        match flag.as_str() {
            "--endpoint" => {
                let Some((value, tail)) = tail.split_first() else {
                    return Err("--endpoint needs a name or path".to_string());
                };
                parsed.endpoint = Endpoint::new(value);
                rest = tail;
            }
            "--state-dir" => {
                let Some((value, tail)) = tail.split_first() else {
                    return Err("--state-dir needs a directory".to_string());
                };
                parsed.state_dir = Some(std::path::PathBuf::from(value));
                rest = tail;
            }
            "--trust-enforce" => {
                parsed.trust_enforce = true;
                rest = tail;
            }
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    Ok(parsed)
}

enum ServiceCommand {
    Install(service::ServiceOptions),
    Uninstall,
    Run(service::ServiceOptions),
}

fn parse_service(args: &[String]) -> Result<ServiceCommand, String> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(format!("service needs a verb\n{USAGE}"));
    };
    let parsed = parse_serve(rest).and_then(|serve| {
        if serve.trust_enforce {
            return Err("--trust-enforce applies to `serve`".to_string());
        }
        Ok(serve)
    })?;
    let options = service::ServiceOptions {
        endpoint: parsed.endpoint,
        state_dir: parsed
            .state_dir
            .or_else(|| Some(service::default_state_dir())),
    };
    match verb.as_str() {
        "install" => Ok(ServiceCommand::Install(options)),
        "uninstall" => Ok(ServiceCommand::Uninstall),
        "run" => Ok(ServiceCommand::Run(options)),
        other => Err(format!("unknown service verb '{other}'\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_arguments_parse() {
        let parsed = parse_serve(&[]).unwrap();
        assert_eq!(parsed.endpoint, Endpoint::default_endpoint());
        assert_eq!(parsed.state_dir, None);
        assert!(!parsed.trust_enforce);

        let args: Vec<String> = [
            "--endpoint",
            "custom",
            "--state-dir",
            "C:\\Program Data\\ScaleFS",
            "--trust-enforce",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_serve(&args).unwrap();
        assert_eq!(parsed.endpoint, Endpoint::new("custom"));
        assert_eq!(
            parsed.state_dir.as_deref(),
            Some(std::path::Path::new("C:\\Program Data\\ScaleFS")),
        );
        assert!(parsed.trust_enforce);

        assert!(parse_serve(&["--endpoint".to_string()]).is_err());
        assert!(parse_serve(&["what".to_string()]).is_err());
    }

    #[test]
    fn service_arguments_parse() {
        match parse_service(&["install".to_string()]).unwrap() {
            ServiceCommand::Install(options) => {
                assert_eq!(options.endpoint, Endpoint::default_endpoint());
                assert_eq!(options.state_dir, Some(service::default_state_dir()));
            }
            _ => panic!("expected install"),
        }
        assert!(matches!(
            parse_service(&["uninstall".to_string()]).unwrap(),
            ServiceCommand::Uninstall
        ));
        let run: Vec<String> = ["run", "--state-dir", "/var/lib/scalefs"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match parse_service(&run).unwrap() {
            ServiceCommand::Run(options) => {
                assert_eq!(
                    options.state_dir.as_deref(),
                    Some(std::path::Path::new("/var/lib/scalefs")),
                );
            }
            _ => panic!("expected run"),
        }
        assert!(parse_service(&[]).is_err());
        assert!(parse_service(&["dance".to_string()]).is_err());
        assert!(
            parse_service(&["install".to_string(), "--trust-enforce".to_string()]).is_err(),
            "--trust-enforce is serve's flag",
        );
    }
}
