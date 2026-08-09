//! Runs a HERALD Home Server over the Client-Server API.
//!
//! ```sh
//! cargo run -p herald-server --bin herald-server -- --insecure-dev-auth
//! ```
//!
//! Authentication is not implemented (§8.1), so the server refuses to start
//! without `--insecure-dev-auth` acknowledging that any connection may assert
//! any identity for reads.

use herald_server::{router, AppState, Hhs, MemoryStore};

const DEFAULT_ADDR: &str = "127.0.0.1:8448";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut addr = DEFAULT_ADDR.to_owned();
    let mut server_name = "herald.localhost".to_owned();
    let mut dev_auth = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = args.next().ok_or("--addr needs a value")?,
            "--server-name" => server_name = args.next().ok_or("--server-name needs a value")?,
            "--insecure-dev-auth" => dev_auth = true,
            "--help" | "-h" => {
                println!(
                    "herald-server [--addr {DEFAULT_ADDR}] [--server-name NAME] --insecure-dev-auth"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    if !dev_auth {
        return Err(
            "refusing to start: no authentication is implemented yet (spec 8.1). \
                    Pass --insecure-dev-auth to run anyway, for local development only."
                .into(),
        );
    }

    eprintln!("WARNING: running with --insecure-dev-auth. Any connection may assert any");
    eprintln!("         identity and read that account's threads. Never expose this.");

    let state = AppState::new(Hhs::new(MemoryStore::new(), server_name.clone()), dev_auth);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("{server_name} listening on ws://{addr}/hcs/v1/ws");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
