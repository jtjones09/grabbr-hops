use clap::{Args, Parser, Subcommand};
use futures::StreamExt;

use std::{collections::HashSet, net::IpAddr, time::Duration};
use thiserror::Error;

use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, ClientConfig, ClientHandle, ClientState,
    ConnectionError, FrontendEvent, FrontendRequest, IpcError, Position, connect_async,
};

#[derive(Debug, Error)]
pub enum CliError {
    /// is the service running?
    #[error("could not connect: `{0}` - is the service running?")]
    ServiceNotRunning(#[from] ConnectionError),
    #[error("error communicating with service: {0}")]
    Ipc(#[from] IpcError),
    /// The service did not say it had handled the command.
    #[error("the service did not confirm the command: {0}")]
    Unconfirmed(String),
    /// The service handled the command and did not carry it out.
    #[error("not done: {0}")]
    NotDone(String),
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

/// How long a command waits for the service to say it handled it.
const CONFIRM_WITHIN: Duration = Duration::from_secs(10);

/// What the service said while it handled a command's requests.
#[derive(Default)]
struct Answer {
    /// every device, as listed after the requests were handled
    devices: Vec<(ClientHandle, ClientConfig, ClientState)>,
    /// devices created while they were handled
    created: Vec<ClientHandle>,
    /// what the service reported meanwhile: refusals, and notices
    errors: Vec<String>,
}

impl Answer {
    fn device(&self, id: ClientHandle) -> Option<(&ClientConfig, &ClientState)> {
        self.devices
            .iter()
            .find(|(h, _, _)| *h == id)
            .map(|(_, c, s)| (c, s))
    }

    /// Pass on what the service reported.
    fn tell(&self) {
        for e in &self.errors {
            eprintln!("{e}");
        }
    }
}

/// A number no other command running now will pick.
fn barrier_number() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    (u64::from(std::process::id()) << 32) | u64::from(nanos)
}

/// The next event, or why none is coming.
async fn next_event(
    rx: &mut AsyncFrontendEventReader,
    deadline: tokio::time::Instant,
) -> Result<FrontendEvent, CliError> {
    loop {
        match tokio::time::timeout_at(deadline, rx.next()).await {
            Err(_) => {
                return Err(CliError::Unconfirmed(format!(
                    "no answer within {} s",
                    CONFIRM_WITHIN.as_secs()
                )));
            }
            Ok(None) => {
                return Err(CliError::Unconfirmed(
                    "the service closed the connection. A service older than this \
                     command closes it on requests it does not know; restart it."
                        .to_string(),
                ));
            }
            // an event a newer service sends that this build cannot read
            Ok(Some(Err(IpcError::Json(_)))) => continue,
            Ok(Some(event)) => return Ok(event?),
        }
    }
}

/// Send `requests`, and return once the service has handled every one.
///
/// A request that has reached the socket has not been acted on. A command
/// that exits there reports success for requests the service refused or has
/// not read yet, and on Windows, where the endpoint is loopback TCP, closing
/// the socket with the service's replies unread resets the connection, which
/// can discard a request the service has not read (#6). So the requests are
/// followed by a listing and a barrier, and everything the service sends is
/// read until the barrier comes back. The listing just before it is the
/// state the requests left.
async fn send(
    rx: &mut AsyncFrontendEventReader,
    tx: &mut AsyncFrontendRequestWriter,
    requests: impl IntoIterator<Item = FrontendRequest>,
) -> Result<Answer, CliError> {
    let n = barrier_number();
    for request in requests {
        tx.request(request).await?;
    }
    tx.request(FrontendRequest::Enumerate()).await?;
    tx.request(FrontendRequest::Barrier(n)).await?;
    let deadline = tokio::time::Instant::now() + CONFIRM_WITHIN;
    let mut answer = Answer::default();
    loop {
        match next_event(rx, deadline).await? {
            FrontendEvent::Barrier(m) if m == n => return Ok(answer),
            FrontendEvent::Enumerate(devices) => answer.devices = devices,
            FrontendEvent::Created(handle, _, _) => answer.created.push(handle),
            FrontendEvent::Error(e) => answer.errors.push(e),
            _ => {}
        }
    }
}

/// Connect, and wait until the service has greeted this connection.
///
/// It sends every new connection its whole state, notices included. Waiting
/// for that first keeps those notices out of the answer to the command.
async fn connect()
-> Result<(AsyncFrontendEventReader, AsyncFrontendRequestWriter, Answer), CliError> {
    let (mut rx, mut tx) = connect_async(Some(Duration::from_millis(500))).await?;
    let deadline = tokio::time::Instant::now() + CONFIRM_WITHIN;
    while !matches!(
        next_event(&mut rx, deadline).await?,
        FrontendEvent::DaemonBuild(_)
    ) {}
    let now = send(&mut rx, &mut tx, []).await?;
    Ok((rx, tx, now))
}

/// Send `request` for device `id`, and fail unless the device then satisfies
/// `done`.
async fn change(
    rx: &mut AsyncFrontendEventReader,
    tx: &mut AsyncFrontendRequestWriter,
    id: ClientHandle,
    request: FrontendRequest,
    done: impl Fn(&ClientConfig, &ClientState) -> bool,
) -> Result<(), CliError> {
    let answer = send(rx, tx, [request]).await?;
    answer.tell();
    match answer.device(id) {
        None => Err(CliError::NotDone(format!("no device with id {id}"))),
        Some((c, s)) if done(c, s) => Ok(()),
        Some(_) => Err(CliError::NotDone(format!("device {id} was not changed"))),
    }
}

/// Fail, after passing on the service's reasons, if it reported any.
fn refused_if_told(answer: &Answer, what: &str) -> Result<(), CliError> {
    answer.tell();
    if answer.errors.is_empty() {
        Ok(())
    } else {
        Err(CliError::NotDone(what.to_string()))
    }
}

pub async fn run(args: CliArgs) -> Result<(), CliError> {
    execute(args.command).await?;
    Ok(())
}

async fn execute(cmd: CliSubcommand) -> Result<(), CliError> {
    let (mut rx, mut tx, now) = connect().await?;
    let (rx, tx) = (&mut rx, &mut tx);
    match cmd {
        CliSubcommand::AddClient(Client {
            hostname,
            port,
            ips,
        }) => {
            // Adding a device from here is the add-device flow too, so pairing
            // prompts may appear on this machine for the next two minutes (#195).
            let made = send(
                rx,
                tx,
                [FrontendRequest::OpenPairing, FrontendRequest::Create],
            )
            .await?;
            made.tell();
            let Some(&handle) = made.created.first() else {
                return Err(CliError::NotDone("no device was created".to_string()));
            };
            let mut edits = vec![];
            if let Some(hostname) = hostname.clone() {
                // Just created: never connected, so no pin.
                edits.push(FrontendRequest::UpdateHostname {
                    handle,
                    hostname: Some(hostname),
                    fingerprint: None,
                });
            }
            if let Some(port) = port {
                edits.push(FrontendRequest::UpdatePort(handle, port));
            }
            if let Some(ips) = ips.clone() {
                edits.push(FrontendRequest::UpdateFixIps(handle, ips));
            }
            let answer = send(rx, tx, edits).await?;
            answer.tell();
            let Some((c, _)) = answer.device(handle) else {
                return Err(CliError::NotDone(format!(
                    "device {handle} was removed while it was being set up"
                )));
            };
            let set = hostname.is_none_or(|h| c.hostname.as_deref() == Some(h.as_str()))
                && port.is_none_or(|p| c.port == p)
                && ips.is_none_or(|ips| same_ips(&c.fix_ips, &ips));
            if !set {
                return Err(CliError::NotDone(format!(
                    "device {handle} was added, but not all of its settings were"
                )));
            }
            println!("added device {handle}");
        }
        CliSubcommand::RemoveClient { id } => {
            // The service refuses a delete that names a different pin than the
            // device has, so the one sent is the one it just listed.
            let Some((_, state)) = now.device(id) else {
                return Err(CliError::NotDone(format!("no device with id {id}")));
            };
            let request = FrontendRequest::Delete {
                handle: id,
                fingerprint: state.peer_fingerprint.clone(),
            };
            let answer = send(rx, tx, [request]).await?;
            answer.tell();
            if answer.device(id).is_some() {
                return Err(CliError::NotDone(format!("device {id} was not removed")));
            }
        }
        CliSubcommand::Activate { id } => {
            let request = FrontendRequest::Activate(id, true);
            change(rx, tx, id, request, |_, s| s.active).await?
        }
        CliSubcommand::Deactivate { id } => {
            let request = FrontendRequest::Activate(id, false);
            change(rx, tx, id, request, |_, s| !s.active).await?
        }
        CliSubcommand::List => {
            for (handle, config, state) in now.devices {
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
        }
        CliSubcommand::SetHost { id, host } => {
            let Some((_, state)) = now.device(id) else {
                return Err(CliError::NotDone(format!("no device with id {id}")));
            };
            let request = FrontendRequest::UpdateHostname {
                handle: id,
                hostname: host.clone(),
                fingerprint: state.peer_fingerprint.clone(),
            };
            change(rx, tx, id, request, |c, _| c.hostname == host).await?
        }
        CliSubcommand::SetPort { id, port } => {
            let request = FrontendRequest::UpdatePort(id, port);
            change(rx, tx, id, request, |c, _| c.port == port).await?
        }
        CliSubcommand::SetPosition { id, pos } => {
            let request = FrontendRequest::UpdatePosition(id, pos);
            change(rx, tx, id, request, |c, _| c.pos == pos).await?
        }
        CliSubcommand::SetIps { id, ips } => {
            let request = FrontendRequest::UpdateFixIps(id, ips.clone());
            change(rx, tx, id, request, |c, _| same_ips(&c.fix_ips, &ips)).await?
        }
        CliSubcommand::EnableCapture => {
            send(rx, tx, [FrontendRequest::EnableCapture]).await?.tell()
        }
        CliSubcommand::EnableEmulation => send(rx, tx, [FrontendRequest::EnableEmulation])
            .await?
            .tell(),
        CliSubcommand::AuthorizeKey {
            description,
            sha256_fingerprint,
        } => {
            let request = FrontendRequest::AuthorizeKey(description, sha256_fingerprint);
            let answer = send(rx, tx, [request]).await?;
            refused_if_told(&answer, "nothing was trusted")?
        }
        CliSubcommand::RemoveAuthorizedKey { sha256_fingerprint } => {
            let request = FrontendRequest::RemoveAuthorizedKey(sha256_fingerprint);
            send(rx, tx, [request]).await?.tell()
        }
        CliSubcommand::SaveConfig => {
            let answer = send(rx, tx, [FrontendRequest::SaveConfiguration]).await?;
            refused_if_told(&answer, "the configuration was not saved")?
        }
    }
    Ok(())
}

fn same_ips(have: &[IpAddr], want: &[IpAddr]) -> bool {
    let have: HashSet<_> = have.iter().collect();
    let want: HashSet<_> = want.iter().collect();
    have == want
}
