//! `hops cli`.
//!
//! Every write command exits 0 only when the service did it and saved it. It
//! exits 1 when the service did not do it, did not say, or said it could not
//! save it: the device commands and `save-config` by the config, the trust
//! commands by the trust store, which the config only copies.

use clap::{Args, Parser, Subcommand};
use futures::{Stream, StreamExt};

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};
use thiserror::Error;

use hops_ipc::{
    AsyncFrontendRequestWriter, ClientConfig, ClientHandle, ClientState, ConnectionError,
    FrontendEvent, FrontendRequest, GRANT_REFUSED, IpcError, NOT_SAVED, Position, TRUST_NOT_SAVED,
    connect_async, identity::canonical_fingerprint,
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
    /// The service carried the command out and said it could not save it.
    #[error("not saved: {0}")]
    NotSaved(String),
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

/// How long a command waits for the service to say it handled it. Long
/// enough that a busy machine, or a service that has only just started, is
/// not reported as not answering: 10 s did that under load, for commands
/// the service then applied. A service that is truly stuck is still named.
const CONFIRM_WITHIN: Duration = Duration::from_secs(30);

/// What the service said while it handled a command's requests.
#[derive(Default)]
struct Answer {
    /// every device, as listed after the requests were handled
    devices: Vec<(ClientHandle, ClientConfig, ClientState)>,
    /// devices created while they were handled
    created: Vec<ClientHandle>,
    /// the devices that may drive this machine, if listed meanwhile
    trusted: Option<HashMap<String, String>>,
    /// the revoked devices, if listed meanwhile
    revoked: Option<HashSet<String>>,
    /// the devices approved here and waiting for the number to be confirmed
    /// on both machines, if listed meanwhile
    pairing: Option<HashSet<String>>,
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

    /// Whether the service reported a notice that begins with `marker`.
    fn said(&self, marker: &str) -> bool {
        self.errors.iter().any(|e| e.starts_with(marker))
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
    rx: &mut (impl Stream<Item = Result<FrontendEvent, IpcError>> + Unpin),
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
/// not read yet, and closing a connection with the service's replies unread
/// could reset it, discarding a request the service had not read, as it did
/// over the loopback TCP endpoint Windows used before its pipe (#6). So the
/// requests are followed by a listing and a barrier, and everything the
/// service sends is read until the barrier comes back. The listing just
/// before it is the state the requests left.
async fn send(
    rx: &mut Events,
    tx: &mut AsyncFrontendRequestWriter,
    requests: impl IntoIterator<Item = FrontendRequest>,
) -> Result<Answer, CliError> {
    let n = barrier_number();
    for request in requests {
        tx.request(request).await?;
    }
    tx.request(FrontendRequest::Enumerate()).await?;
    tx.request(FrontendRequest::Barrier(n)).await?;
    read_until(rx, n, tokio::time::Instant::now() + CONFIRM_WITHIN).await
}

/// What this connection's events are read from.
type Events = hops_ipc::AsyncFrontendEventReader;

/// Everything the service sends until barrier `n` comes back.
///
/// Every frontend receives every event, so another command's barrier can
/// arrive first. Only this command's own number ends it.
async fn read_until(
    rx: &mut (impl Stream<Item = Result<FrontendEvent, IpcError>> + Unpin),
    n: u64,
    deadline: tokio::time::Instant,
) -> Result<Answer, CliError> {
    let mut answer = Answer::default();
    loop {
        match next_event(rx, deadline).await? {
            FrontendEvent::Barrier(m) if m == n => return Ok(answer),
            FrontendEvent::Enumerate(devices) => answer.devices = devices,
            FrontendEvent::Created(handle, _, _) => answer.created.push(handle),
            FrontendEvent::AuthorizedUpdated(keys) => answer.trusted = Some(keys),
            FrontendEvent::RevokedUpdated(r) => answer.revoked = Some(r.into_keys().collect()),
            FrontendEvent::TrustUpdated(t) => {
                answer.pairing = Some(
                    t.into_iter()
                        .filter(|(_, t)| t.pending)
                        .map(|(fp, _)| fp)
                        .collect(),
                )
            }
            FrontendEvent::Error(e) => answer.errors.push(e),
            _ => {}
        }
    }
}

/// Wait until the service begins its greeting to this connection.
///
/// A service greets with its build first. One that sends the rest of its
/// greeting without it predates the barrier every command ends on, and closes
/// the connection when it receives one.
async fn greeted(
    rx: &mut (impl Stream<Item = Result<FrontendEvent, IpcError>> + Unpin),
    deadline: tokio::time::Instant,
) -> Result<(), CliError> {
    loop {
        match next_event(rx, deadline).await? {
            FrontendEvent::DaemonBuild(_) => return Ok(()),
            // in every greeting, after the build
            FrontendEvent::PublicKeyFingerprint(_) => {
                return Err(CliError::Unconfirmed(
                    "the service is older than this command. Restart the service, \
                     then run the command again."
                        .to_string(),
                ));
            }
            _ => {}
        }
    }
}

/// Connect, and wait until the service has greeted this connection.
///
/// It sends every new connection its whole state, notices included. Waiting
/// for that first keeps those notices out of the answer to the command.
async fn connect() -> Result<(Events, AsyncFrontendRequestWriter, Answer), CliError> {
    let (mut rx, mut tx) = connect_async(Some(Duration::from_millis(500))).await?;
    greeted(&mut rx, tokio::time::Instant::now() + CONFIRM_WITHIN).await?;
    let now = send(&mut rx, &mut tx, []).await?;
    Ok((rx, tx, now))
}

/// Send `request` for device `id`, and fail unless the device then satisfies
/// `done` and the change was saved.
async fn change(
    rx: &mut Events,
    tx: &mut AsyncFrontendRequestWriter,
    id: ClientHandle,
    request: FrontendRequest,
    done: impl Fn(&ClientConfig, &ClientState) -> bool,
) -> Result<(), CliError> {
    let answer = send(rx, tx, [request]).await?;
    answer.tell();
    changed(&answer, id, done)
}

/// Whether device `id` is listed in `answer`, satisfies `done`, and was saved.
fn changed(
    answer: &Answer,
    id: ClientHandle,
    done: impl Fn(&ClientConfig, &ClientState) -> bool,
) -> Result<(), CliError> {
    match answer.device(id) {
        None => Err(CliError::NotDone(format!("no device with id {id}"))),
        Some((c, s)) if done(c, s) => saved(answer, NOT_SAVED),
        Some(_) => Err(CliError::NotDone(format!("device {id} was not changed"))),
    }
}

/// Fail if the service said a change was not saved, by the notice that begins
/// with `marker`. Any other notice is passed on and is not a failure.
fn saved(answer: &Answer, marker: &str) -> Result<(), CliError> {
    if !answer.said(marker) {
        Ok(())
    } else if marker == TRUST_NOT_SAVED {
        Err(CliError::NotSaved(
            "the change is in effect, and is undone if the service restarts before it \
             saves it"
                .to_string(),
        ))
    } else {
        Err(CliError::NotSaved(
            "the change is in effect, and is lost when the service restarts".to_string(),
        ))
    }
}

/// Whether the grant of `fp` was made and saved.
///
/// Decided by what the service said about this grant: every refusal begins
/// with [`GRANT_REFUSED`], and a grant made always lists the trusted devices.
/// The listing names only devices that may drive this machine, so a device
/// this machine may drive is trusted without appearing in it.
fn granted(answer: &Answer, before: &Answer, fp: &str) -> Result<(), CliError> {
    let fp = canonical_fingerprint(fp).unwrap_or_else(|| fp.to_string());
    let listed = answer
        .trusted
        .as_ref()
        .or(before.trusted.as_ref())
        .is_some_and(|t| t.contains_key(&fp));
    if !listed {
        if answer.said(GRANT_REFUSED) {
            return Err(CliError::NotDone("nothing was trusted".to_string()));
        }
        if answer.trusted.is_none() {
            return Err(CliError::Unconfirmed(format!(
                "the service did not say it trusted {fp}"
            )));
        }
    }
    saved(answer, TRUST_NOT_SAVED)?;
    // A new pairing is approved, not trusted: it grants nothing until the
    // number is confirmed on both machines, in the hops app (#167).
    let pending = answer.pairing.as_ref().is_some_and(|p| p.contains(&fp));
    if pending {
        println!(
            "approved {fp}: pairing finishes once the number is confirmed in the hops \
             app on both machines"
        );
    } else {
        println!("trusted {fp}");
    }
    Ok(())
}

/// Whether `fp` was revoked and the revocation saved.
fn revoked(answer: &Answer, before: &Answer, fp: &str) -> Result<(), CliError> {
    // the spelling the service revokes under
    let fp = canonical_fingerprint(fp).unwrap_or_else(|| fp.trim().to_lowercase());
    let listed = answer
        .revoked
        .as_ref()
        .or(before.revoked.as_ref())
        .is_some_and(|r| r.contains(&fp));
    if !listed {
        return Err(CliError::NotDone(format!("{fp} was not revoked")));
    }
    saved(answer, TRUST_NOT_SAVED)
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
            saved(&made, NOT_SAVED)?;
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
            saved(&answer, NOT_SAVED)?;
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
            // removing a paired device also revokes it
            saved(&answer, NOT_SAVED)?;
            saved(&answer, TRUST_NOT_SAVED)?;
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
            let request = FrontendRequest::AuthorizeKey(description, sha256_fingerprint.clone());
            let answer = send(rx, tx, [request]).await?;
            answer.tell();
            granted(&answer, &now, &sha256_fingerprint)?
        }
        CliSubcommand::RemoveAuthorizedKey { sha256_fingerprint } => {
            let request = FrontendRequest::RemoveAuthorizedKey(sha256_fingerprint.clone());
            let answer = send(rx, tx, [request]).await?;
            answer.tell();
            revoked(&answer, &now, &sha256_fingerprint)?
        }
        CliSubcommand::SaveConfig => {
            let answer = send(rx, tx, [FrontendRequest::SaveConfiguration]).await?;
            answer.tell();
            saved(&answer, NOT_SAVED)?
        }
    }
    Ok(())
}

fn same_ips(have: &[IpAddr], want: &[IpAddr]) -> bool {
    let have: HashSet<_> = have.iter().collect();
    let want: HashSet<_> = want.iter().collect();
    have == want
}

#[cfg(test)]
mod tests {
    //! How a command reads the service's answer, fed the events a service
    //! sends. The commands against a running service are in the hops crate's
    //! `tests/cli_writes.rs`.
    use super::*;
    use hops_ipc::Build;

    fn events(
        list: Vec<FrontendEvent>,
    ) -> impl Stream<Item = Result<FrontendEvent, IpcError>> + Unpin {
        // then nothing more, as from a service that has sent all it will
        futures::stream::iter(list.into_iter().map(Ok)).chain(futures::stream::pending())
    }

    fn soon() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(5)
    }

    fn device(id: ClientHandle, pos: Position) -> (ClientHandle, ClientConfig, ClientState) {
        let config = ClientConfig {
            pos,
            ..Default::default()
        };
        (id, config, ClientState::default())
    }

    // LEDGER T25 | class B | 1 return value: hops_cli::read_until
    #[tokio::test]
    async fn a_command_ends_on_its_own_barrier_only() {
        let mut rx = events(vec![
            // another command's, on another connection
            FrontendEvent::Barrier(7),
            FrontendEvent::Enumerate(vec![device(0, Position::Right)]),
            FrontendEvent::Barrier(9),
        ]);
        let answer = read_until(&mut rx, 9, soon()).await.expect("an answer");
        assert!(
            answer.device(0).is_some(),
            "the command ended on another command's barrier, before the \
             listing its own requests left"
        );
    }

    // LEDGER T26 | class B | 1 return value: hops_cli::changed, saved, granted
    #[test]
    fn a_verdict_rests_on_what_the_service_did_to_this_command() {
        let listed = Answer {
            devices: vec![device(0, Position::Left)],
            ..Default::default()
        };
        assert!(
            matches!(
                changed(&listed, 0, |c, _| c.pos == Position::Right),
                Err(CliError::NotDone(ref e)) if e.contains("was not changed")
            ),
            "a device the service listed unchanged was reported changed"
        );

        // A notice about something else is passed on, and fails nothing.
        let other = Answer {
            devices: vec![device(0, Position::Right)],
            errors: vec![format!("{GRANT_REFUSED}: another frontend's grant")],
            ..Default::default()
        };
        assert!(changed(&other, 0, |c, _| c.pos == Position::Right).is_ok());
        assert!(
            saved(&other, NOT_SAVED).is_ok(),
            "save-config failed on a notice that was not about the save"
        );
        let unsaved = Answer {
            devices: vec![device(0, Position::Right)],
            errors: vec![format!("{NOT_SAVED}: config.toml was left as it is")],
            ..Default::default()
        };
        assert!(
            matches!(
                changed(&unsaved, 0, |c, _| c.pos == Position::Right),
                Err(CliError::NotSaved(_))
            ),
            "a change the service said it could not save was reported saved"
        );

        // A grant is decided by the grant: a config the service could not
        // save does not make a device it trusted untrusted.
        let fp = ["ab"; 32].join(":");
        let made = Answer {
            trusted: Some(HashMap::from([(fp.clone(), "laptop".to_string())])),
            errors: vec![format!("{NOT_SAVED}: config.toml was left as it is")],
            ..Default::default()
        };
        assert!(granted(&made, &Answer::default(), &fp.to_uppercase()).is_ok());
        // a device this machine may drive: trusted, and not in the listing
        let outbound = Answer {
            trusted: Some(HashMap::new()),
            ..Default::default()
        };
        assert!(
            granted(&outbound, &Answer::default(), &fp).is_ok(),
            "a grant for a device this machine may drive was reported not made"
        );
        let refused = Answer {
            trusted: None,
            errors: vec![format!("{GRANT_REFUSED}: no pairing request is waiting")],
            ..Default::default()
        };
        assert!(matches!(
            granted(&refused, &Answer::default(), &fp),
            Err(CliError::NotDone(_))
        ));
    }

    // LEDGER T27 | class B | 1 return value: hops_cli::greeted
    #[tokio::test]
    async fn a_service_older_than_the_command_is_named_as_such() {
        let build = Build {
            version: "0.13.0".to_string(),
            commit: "unknown".to_string(),
        };
        let mut current = events(vec![
            FrontendEvent::DaemonBuild(build),
            FrontendEvent::PublicKeyFingerprint("fp".to_string()),
        ]);
        assert!(greeted(&mut current, soon()).await.is_ok());

        // a greeting from before the build event: no build, then the rest
        let mut older = events(vec![
            FrontendEvent::Enumerate(vec![]),
            FrontendEvent::PublicKeyFingerprint("fp".to_string()),
            FrontendEvent::AuthorizedUpdated(HashMap::new()),
        ]);
        match greeted(&mut older, soon()).await {
            Err(CliError::Unconfirmed(e)) => assert!(
                e.contains("older than this command"),
                "the command did not say the service is older: {e}"
            ),
            other => panic!(
                "a service older than the command was waited on, not named: {:?}",
                other.map_err(|e| e.to_string())
            ),
        }
    }
}
