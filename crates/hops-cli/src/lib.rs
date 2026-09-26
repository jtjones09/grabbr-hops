use clap::{Args, Parser, Subcommand};
use futures::StreamExt;

use std::{net::IpAddr, time::Duration};
use thiserror::Error;

use hops_ipc::{
    ClientHandle, ConnectionError, FrontendEvent, FrontendRequest, IpcError, Position,
    connect_async,
};

#[derive(Debug, Error)]
pub enum CliError {
    /// is the service running?
    #[error("could not connect: `{0}` - is the service running?")]
    ServiceNotRunning(#[from] ConnectionError),
    #[error("error communicating with service: {0}")]
    Ipc(#[from] IpcError),
}

#[derive(Parser, Clone, Debug, PartialEq, Eq)]
#[command(name = "hops-cli", about = "hops CLI interface")]
pub struct CliArgs {
    #[command(subcommand)]
    command: CliSubcommand,
}

#[derive(Args, Clone, Debug, PartialEq, Eq)]
struct Client {
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    ips: Option<Vec<IpAddr>>,
}

#[derive(Clone, Subcommand, Debug, PartialEq, Eq)]
enum CliSubcommand {
    /// add a new client
    AddClient(Client),
    /// remove an existing client
    RemoveClient { id: ClientHandle },
    /// activate a client
    Activate { id: ClientHandle },
    /// deactivate a client
    Deactivate { id: ClientHandle },
    /// list configured clients
    List,
    /// change hostname
    SetHost {
        id: ClientHandle,
        host: Option<String>,
    },
    /// change port
    SetPort { id: ClientHandle, port: u16 },
    /// set position
    SetPosition { id: ClientHandle, pos: Position },
    /// set ips
    SetIps { id: ClientHandle, ips: Vec<IpAddr> },
    /// re-enable capture
    EnableCapture,
    /// re-enable emulation
    EnableEmulation,
    /// authorize a public key
    AuthorizeKey {
        description: String,
        sha256_fingerprint: String,
    },
    /// deauthorize a public key
    RemoveAuthorizedKey { sha256_fingerprint: String },
    /// save configuration to file
    SaveConfig,
}

/// The pin of device `id` as the daemon has it now: `None` (after saying so)
/// if there is no such device.
///
/// The daemon refuses a delete or rename that names a different pin than the
/// device has, so the one the CLI acts on is the one it just read.
async fn pin_of(
    rx: &mut hops_ipc::AsyncFrontendEventReader,
    tx: &mut hops_ipc::AsyncFrontendRequestWriter,
    id: ClientHandle,
) -> Result<Option<Option<String>>, CliError> {
    tx.request(FrontendRequest::Enumerate()).await?;
    while let Some(e) = rx.next().await {
        if let FrontendEvent::Enumerate(clients) = e? {
            let pin = clients
                .into_iter()
                .find(|(h, _, _)| *h == id)
                .map(|(_, _, s)| s.peer_fingerprint);
            if pin.is_none() {
                eprintln!("no device with id {id}");
            }
            return Ok(pin);
        }
    }
    Ok(None)
}

pub async fn run(args: CliArgs) -> Result<(), CliError> {
    execute(args.command).await?;
    Ok(())
}

async fn execute(cmd: CliSubcommand) -> Result<(), CliError> {
    let (mut rx, mut tx) = connect_async(Some(Duration::from_millis(500))).await?;
    match cmd {
        CliSubcommand::AddClient(Client {
            hostname,
            port,
            ips,
        }) => {
            // Adding a device from here is the add-device flow too, so pairing
            // prompts may appear on this machine for the next two minutes (#195).
            tx.request(FrontendRequest::OpenPairing).await?;
            tx.request(FrontendRequest::Create).await?;
            while let Some(e) = rx.next().await {
                if let FrontendEvent::Created(handle, _, _) = e? {
                    if let Some(hostname) = hostname {
                        // Just created: never connected, so no pin.
                        tx.request(FrontendRequest::UpdateHostname {
                            handle,
                            hostname: Some(hostname),
                            fingerprint: None,
                        })
                        .await?;
                    }
                    if let Some(port) = port {
                        tx.request(FrontendRequest::UpdatePort(handle, port))
                            .await?;
                    }
                    if let Some(ips) = ips {
                        tx.request(FrontendRequest::UpdateFixIps(handle, ips))
                            .await?;
                    }
                    break;
                }
            }
        }
        CliSubcommand::RemoveClient { id } => {
            if let Some(fingerprint) = pin_of(&mut rx, &mut tx, id).await? {
                tx.request(FrontendRequest::Delete {
                    handle: id,
                    fingerprint,
                })
                .await?
            }
        }
        CliSubcommand::Activate { id } => tx.request(FrontendRequest::Activate(id, true)).await?,
        CliSubcommand::Deactivate { id } => {
            tx.request(FrontendRequest::Activate(id, false)).await?
        }
        CliSubcommand::List => {
            tx.request(FrontendRequest::Enumerate()).await?;
            while let Some(e) = rx.next().await {
                if let FrontendEvent::Enumerate(clients) = e? {
                    for (handle, config, state) in clients {
                        let host = config.hostname.unwrap_or("unknown".to_owned());
                        let port = config.port;
                        let pos = config.pos;
                        let active = state.active;
                        let ips = state.ips;
                        let pin = state.peer_fingerprint.unwrap_or("none".to_owned());
                        println!(
                            "id {handle}: {host}:{port} ({pos}) active: {active}, ips: {ips:?}, \
                             fingerprint: {pin}"
                        );
                    }
                    break;
                }
            }
        }
        CliSubcommand::SetHost { id, host } => {
            if let Some(fingerprint) = pin_of(&mut rx, &mut tx, id).await? {
                tx.request(FrontendRequest::UpdateHostname {
                    handle: id,
                    hostname: host,
                    fingerprint,
                })
                .await?
            }
        }
        CliSubcommand::SetPort { id, port } => {
            tx.request(FrontendRequest::UpdatePort(id, port)).await?
        }
        CliSubcommand::SetPosition { id, pos } => {
            tx.request(FrontendRequest::UpdatePosition(id, pos)).await?
        }
        CliSubcommand::SetIps { id, ips } => {
            tx.request(FrontendRequest::UpdateFixIps(id, ips)).await?
        }
        CliSubcommand::EnableCapture => tx.request(FrontendRequest::EnableCapture).await?,
        CliSubcommand::EnableEmulation => tx.request(FrontendRequest::EnableEmulation).await?,
        CliSubcommand::AuthorizeKey {
            description,
            sha256_fingerprint,
        } => {
            tx.request(FrontendRequest::AuthorizeKey(
                description,
                sha256_fingerprint,
            ))
            .await?
        }
        CliSubcommand::RemoveAuthorizedKey { sha256_fingerprint } => {
            tx.request(FrontendRequest::RemoveAuthorizedKey(sha256_fingerprint))
                .await?
        }
        CliSubcommand::SaveConfig => tx.request(FrontendRequest::SaveConfiguration).await?,
    }
    Ok(())
}
