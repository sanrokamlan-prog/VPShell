#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::{path::Path, sync::Arc, time::Duration};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::net::TcpListener;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use vpshell_lib::relay::{
    JsonLineAudit, RelayClientConfig, RelayLimits, RelayServerConfig, RelayTarget, RelayToken,
    run_local_connector, serve,
};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(code) = run().await {
        eprintln!("vpshell-relay-error={code}");
        std::process::exit(2);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn main() {
    eprintln!("vpshell-relay-is-desktop-only");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("token") => {
            let path = required_path(&mut arguments, "--output")?;
            if arguments.next().is_some() {
                return Err("relay-cli-arguments-invalid");
            }
            RelayToken::generate_file(Path::new(&path))?;
            eprintln!("relay-token-created");
            Ok(())
        }
        Some("serve") => {
            let listen = parse_socket_addr(&required_value(&mut arguments, "--listen")?)?;
            let token_path = required_path(&mut arguments, "--token-file")?;
            let mut targets = Vec::new();
            let mut audit_path = None;
            let mut limits = RelayLimits::default();
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--allow-target" => targets.push(RelayTarget::parse(
                        &arguments.next().ok_or("relay-cli-arguments-invalid")?,
                    )?),
                    "--audit-file" => {
                        audit_path = Some(arguments.next().ok_or("relay-cli-arguments-invalid")?)
                    }
                    "--max-connections" => limits.max_connections = parse_number(&mut arguments)?,
                    "--max-per-ip" => limits.max_connections_per_ip = parse_number(&mut arguments)?,
                    "--auth-per-minute" => {
                        limits.auth_attempts_per_minute = parse_number(&mut arguments)?
                    }
                    "--max-bytes" => limits.max_session_bytes = parse_number(&mut arguments)?,
                    "--idle-seconds" => {
                        limits.idle_timeout = Duration::from_secs(parse_number(&mut arguments)?)
                    }
                    "--max-seconds" => {
                        limits.max_session_duration =
                            Duration::from_secs(parse_number(&mut arguments)?)
                    }
                    _ => return Err("relay-cli-arguments-invalid"),
                }
            }
            let token = Arc::new(RelayToken::load(Path::new(&token_path))?);
            let server_config = RelayServerConfig {
                allowed_targets: targets,
                limits,
            };
            server_config.validate()?;
            let audit: Arc<dyn vpshell_lib::relay::RelayAuditSink> = match audit_path {
                Some(path) if path != "-" => Arc::new(JsonLineAudit::file(Path::new(&path))?),
                _ => Arc::new(JsonLineAudit::stdout()),
            };
            let listener = TcpListener::bind(listen)
                .await
                .map_err(|_| "relay-listener-bind-failed")?;
            let address = listener
                .local_addr()
                .map_err(|_| "relay-listener-bind-failed")?;
            eprintln!("relay-listening={address}");
            serve(
                listener,
                server_config,
                token,
                audit,
                CancellationToken::new(),
            )
            .await
        }
        Some("connect") => {
            let relay_endpoint = required_value(&mut arguments, "--relay")?;
            let listen = parse_socket_addr(&required_value(&mut arguments, "--listen")?)?;
            let target = RelayTarget::parse(&required_value(&mut arguments, "--target")?)?;
            let token_path = required_path(&mut arguments, "--token-file")?;
            if arguments.next().is_some() {
                return Err("relay-cli-arguments-invalid");
            }
            if !listen.ip().is_loopback() {
                return Err("relay-local-listener-must-be-loopback");
            }
            let token = Arc::new(RelayToken::load(Path::new(&token_path))?);
            let listener = TcpListener::bind(listen)
                .await
                .map_err(|_| "relay-local-listener-failed")?;
            let address = listener
                .local_addr()
                .map_err(|_| "relay-local-listener-failed")?;
            eprintln!("relay-local-listening={address}");
            let relay_config = RelayClientConfig {
                relay_endpoint,
                target,
                connect_timeout: Duration::from_secs(10),
                handshake_timeout: Duration::from_secs(10),
            };
            relay_config
                .validate()
                .map_err(|_| "relay-client-config-invalid")?;
            let cancellation = CancellationToken::new();
            run_local_connector(listener, relay_config, token, cancellation).await
        }
        _ => Err("relay-cli-usage"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn required_value(
    arguments: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, &'static str> {
    let argument = arguments.next().ok_or("relay-cli-arguments-invalid")?;
    if argument != flag {
        return Err("relay-cli-arguments-invalid");
    }
    arguments
        .next()
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or("relay-cli-arguments-invalid")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn required_path(
    arguments: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, &'static str> {
    required_value(arguments, flag)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_socket_addr(value: &str) -> Result<std::net::SocketAddr, &'static str> {
    value.parse().map_err(|_| "relay-listener-address-invalid")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_number<T: std::str::FromStr>(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<T, &'static str> {
    arguments
        .next()
        .ok_or("relay-cli-arguments-invalid")?
        .parse()
        .map_err(|_| "relay-cli-arguments-invalid")
}
