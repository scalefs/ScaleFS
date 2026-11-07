use scalefs_daemon::service;
use scalefs_ipc::endpoint::Endpoint;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

const USAGE: &str = "usage: scalefsd serve [--endpoint <name-or-path>] \
                     [--state-dir <dir>] [--trust-enforce] [--metadata-cache <MiB>]\n\
                     |      scalefsd service <install|uninstall|run> \
                     [--endpoint <name-or-path>] [--state-dir <dir>]\n\
                     |      scalefsd shell register [--endpoint <name-or-path>] \
                     [--trust-registering-user] [--replace]\n\
                     |      scalefsd shell unregister [--endpoint <name-or-path>]\n\
                     |      scalefsd version";

fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("serve") => match parse_serve(&args[1..]) {
            Ok(parsed) => {
                #[cfg(unix)]
                service::arm_termination_signals(&parsed.endpoint);
                #[cfg(windows)]
                service::arm_console_handler(&parsed.endpoint);
                if let Some(mib) = parsed.metadata_cache_mib {
                    scalefs_core::set_default_metadata_cache(mib << 20);
                }
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
        #[cfg(windows)]
        Some("shell") => match parse_shell(&args[1..]) {
            Ok(ShellCommand::Register(endpoint, trust, replace)) => {
                report(service::shell_register(&endpoint, trust, replace))
            }
            Ok(ShellCommand::Unregister) => report(service::shell_unregister()),
            Err(message) => {
                eprintln!("scalefsd: {message}");
                2
            }
        },
        #[cfg(windows)]
        Some("session-announce") => {
            let change = args
                .get(1)
                .and_then(|word| scalefs_shell::announce::Change::from_word(word));
            let letter = args
                .get(2)
                .and_then(|text| text.chars().next())
                .filter(char::is_ascii_alphabetic);
            match (change, letter) {
                (Some(change), Some(letter)) => {
                    scalefs_shell::announce::announce_from_helper(letter, change);
                    0
                }
                _ => 2,
            }
        }
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

#[cfg(windows)]
#[derive(Debug, PartialEq)]
enum ShellCommand {
    Register(Endpoint, service::ShellTrust, bool),
    Unregister,
}

#[cfg(windows)]
fn parse_shell(args: &[String]) -> Result<ShellCommand, String> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(format!("shell needs a verb\n{USAGE}"));
    };
    let mut endpoint = Endpoint::default_endpoint();
    let mut trust = service::ShellTrust::Service;
    let mut replace = false;
    let mut flags = rest.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--endpoint" => {
                let value = flags
                    .next()
                    .ok_or_else(|| format!("--endpoint needs a value\n{USAGE}"))?;
                endpoint = Endpoint::new(value);
            }
            "--trust-registering-user" if verb == "register" => {
                trust = service::ShellTrust::RegisteringUser;
            }
            "--replace" if verb == "register" => replace = true,
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    match verb.as_str() {
        "register" => Ok(ShellCommand::Register(endpoint, trust, replace)),
        "unregister" => Ok(ShellCommand::Unregister),
        other => Err(format!("unknown shell verb '{other}'\n{USAGE}")),
    }
}

struct ServeArgs {
    endpoint: Endpoint,
    state_dir: Option<std::path::PathBuf>,
    trust_enforce: bool,
    metadata_cache_mib: Option<usize>,
}

const METADATA_CACHE_MAX_MIB: usize = 1 << 20;

fn parse_serve(args: &[String]) -> Result<ServeArgs, String> {
    let mut parsed = ServeArgs {
        endpoint: Endpoint::default_endpoint(),
        state_dir: None,
        trust_enforce: false,
        metadata_cache_mib: None,
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
            "--metadata-cache" => {
                let Some((value, tail)) = tail.split_first() else {
                    return Err("--metadata-cache needs a size in MiB".to_string());
                };
                let mib: usize = value
                    .parse()
                    .ok()
                    .filter(|mib| (1..=METADATA_CACHE_MAX_MIB).contains(mib))
                    .ok_or_else(|| {
                        format!(
                            "--metadata-cache takes a whole number of MiB from 1 to \
                             {METADATA_CACHE_MAX_MIB}, not '{value}'"
                        )
                    })?;
                parsed.metadata_cache_mib = Some(mib);
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
        if serve.metadata_cache_mib.is_some() {
            return Err("--metadata-cache applies to `serve`".to_string());
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
        assert_eq!(parsed.metadata_cache_mib, None);

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
    fn the_metadata_cache_budget_parses_in_mib() {
        let args = |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
        let parsed = parse_serve(&args(&["--metadata-cache", "64"])).unwrap();
        assert_eq!(parsed.metadata_cache_mib, Some(64));
        for bad in ["0", "-1", "lots", "1.5", "1048577"] {
            assert!(
                parse_serve(&args(&["--metadata-cache", bad])).is_err(),
                "{bad}"
            );
        }
        assert!(parse_serve(&args(&["--metadata-cache"])).is_err());
        assert!(
            parse_service(&args(&["install", "--metadata-cache", "64"])).is_err(),
            "--metadata-cache is serve's flag"
        );
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

    #[cfg(windows)]
    #[test]
    fn shell_arguments_parse() {
        let args = |line: &str| -> Vec<String> { line.split(' ').map(str::to_string).collect() };
        assert_eq!(
            parse_shell(&args("register")).unwrap(),
            ShellCommand::Register(
                Endpoint::default_endpoint(),
                service::ShellTrust::Service,
                false
            )
        );
        assert_eq!(
            parse_shell(&args(
                "register --endpoint dev --trust-registering-user --replace"
            ))
            .unwrap(),
            ShellCommand::Register(
                Endpoint::new("dev"),
                service::ShellTrust::RegisteringUser,
                true
            )
        );
        assert_eq!(
            parse_shell(&args("unregister --endpoint dev")).unwrap(),
            ShellCommand::Unregister
        );
        assert!(parse_shell(&args("unregister --trust-registering-user")).is_err());
        assert!(parse_shell(&args("unregister --replace")).is_err());
        assert!(parse_shell(&args("register --endpoint")).is_err());
        assert!(parse_shell(&[]).is_err());
    }
}
