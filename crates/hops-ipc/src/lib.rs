use std::{
    collections::{HashMap, HashSet},
    env::VarError,
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    time::{Duration, Instant},
};
use thiserror::Error;

#[cfg(unix)]
use std::{
    env,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

mod connect;
mod connect_async;
mod listen;
mod ownership;
pub mod pairing;
pub mod token;

pub use connect::{FrontendEventReader, FrontendRequestWriter, connect, connect_to};
pub use connect_async::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, connect_async, connect_async_to,
};
pub use listen::AsyncFrontendListener;
pub use pairing::{PairingCode, PairingError};

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error(transparent)]
    SocketPath(#[from] SocketPathError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("connection timed out")]
    Timeout,
    /// A frontend on this platform cannot dial that kind of endpoint.
    #[error("a frontend here cannot connect to {0}")]
    UnsupportedEndpoint(DaemonEndpoint),
}

#[derive(Debug, Error)]
pub enum IpcListenerCreationError {
    #[error("could not determine socket-path: `{0}`")]
    SocketPath(#[from] SocketPathError),
    #[error("service already running!")]
    AlreadyRunning,
    /// The endpoint could not be bound, for a reason other than a daemon
    /// holding it.
    #[error("could not listen on {endpoint}: {source}")]
    Bind {
        endpoint: DaemonEndpoint,
        source: io::Error,
    },
    /// The lock that stops a second daemon starting could not be taken, for a
    /// reason other than another daemon holding it.
    #[error("could not lock {}: {source}. {hint}", .path.display())]
    Lock {
        path: std::path::PathBuf,
        source: io::Error,
        /// What to do about it, in words.
        hint: String,
    },
    /// A socket file no daemon answers on, which could not be removed.
    #[error(
        "nothing answers on {}, and it could not be removed: {source}. If no hops \
         daemon is running, remove it and start hops again.",
        .path.display()
    )]
    StaleSocket {
        path: std::path::PathBuf,
        source: io::Error,
    },
    /// Where the token frontends present is kept could not be worked out.
    #[error("could not work out where the IPC token is kept: {0}")]
    TokenPath(io::Error),
    /// The token frontends present could not be read or created.
    #[error("could not read or create the IPC token {}: {source}. {hint}", .path.display())]
    Token {
        path: std::path::PathBuf,
        source: io::Error,
        /// What to do about it, in words.
        hint: String,
    },
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error occured: `{0}`")]
    Io(#[from] io::Error),
    #[error("invalid json: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Listen(#[from] IpcListenerCreationError),
}

pub const DEFAULT_PORT: u16 = 4242;

#[derive(Debug, Default, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Position {
    #[default]
    Left,
    Right,
    Top,
    Bottom,
}

impl Position {
    pub fn opposite(&self) -> Self {
        match self {
            Position::Left => Position::Right,
            Position::Right => Position::Left,
            Position::Top => Position::Bottom,
            Position::Bottom => Position::Top,
        }
    }
}

#[derive(Debug, Error)]
#[error("not a valid position: {pos}")]
pub struct PositionParseError {
    pos: String,
}

impl FromStr for Position {
    type Err = PositionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "left" => Ok(Self::Left),
            "right" => Ok(Self::Right),
            "top" => Ok(Self::Top),
            "bottom" => Ok(Self::Bottom),
            _ => Err(PositionParseError { pos: s.into() }),
        }
    }
}

impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Position::Left => "left",
                Position::Right => "right",
                Position::Top => "top",
                Position::Bottom => "bottom",
            }
        )
    }
}

impl TryFrom<&str> for Position {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "left" => Ok(Position::Left),
            "right" => Ok(Position::Right),
            "top" => Ok(Position::Top),
            "bottom" => Ok(Position::Bottom),
            _ => Err(()),
        }
    }
}

/// A node's rectangle in the unified virtual-desktop space, for spatial
/// (coordinate-based) edge crossing. `None` on a client means "use the edge-based
/// `pos` model" — the default until the layout canvas (P4) assigns geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// hostname of this client
    pub hostname: Option<String>,
    /// fix ips, determined by the user
    pub fix_ips: Vec<IpAddr>,
    /// both active_addr and addrs can be None / empty so port needs to be stored seperately
    pub port: u16,
    /// position of a client on screen
    pub pos: Position,
    /// enter hook
    pub cmd: Option<String>,
    /// spatial geometry (rect in the virtual desktop) for coordinate-based
    /// crossing; `None` = use the edge-based `pos` model. Additive P4 layout
    /// foundation — set by the layout canvas, read by coordinate crossing.
    #[serde(default)]
    pub geometry: Option<Geometry>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            hostname: Default::default(),
            fix_ips: Default::default(),
            pos: Default::default(),
            cmd: None,
            geometry: None,
        }
    }
}

pub type ClientHandle = u64;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientState {
    /// events should be sent to and received from the client
    pub active: bool,
    /// `active` address of the client, used to send data to.
    /// This should generally be the socket address where data
    /// was last received from.
    pub active_addr: Option<SocketAddr>,
    /// tracks whether or not the client is available for emulation
    pub alive: bool,
    /// ips from dns
    pub dns_ips: Vec<IpAddr>,
    /// all ip addresses associated with a particular client
    /// e.g. Laptops usually have at least an ethernet and a wifi port
    /// which have different ip addresses
    pub ips: HashSet<IpAddr>,
    /// client has pressed keys
    pub has_pressed_keys: bool,
    /// dns resolving in progress
    pub resolving: bool,
    /// Peer's build short commit hash from the [`Hello`] proto
    /// event. `None` means we haven't received a Hello yet — either
    /// the connection is fresh, or the peer is on an older build
    /// that predates the Hello event. The frontend uses this to
    /// soft-warn on version mismatch.
    pub peer_commit: Option<[u8; 8]>,
    /// Capability bits advertised by the peer via the `Capability`
    /// proto event (see `hops_proto::caps`). `None` means no Capability
    /// event was received — a fresh connection or a peer predating the
    /// event; optional features are gated on these bits and degrade to
    /// the pre-capability behavior when absent. Mirrors `peer_commit`.
    #[serde(default)]
    pub peer_caps: Option<u32>,
    /// Leaf-cert SHA-256 fingerprint of the connected peer (the receiver this
    /// outgoing client dials), read from the completed TLS handshake. `None`
    /// until a connection completes; then RETAINED as the client's last-known
    /// identity — unlike `peer_commit`/`peer_caps` it is NOT cleared on
    /// disconnect (it pins the reconnect dial, see `connect`). It is cleared
    /// only when the target address config changes (hostname / fix_ips) or trust
    /// in it is revoked. It IS persisted (`[[clients]] fingerprint`) so the device
    /// join works from a cold start and the pin survives a restart — meaning a
    /// restart does NOT clear a bad pin, and the on-disk value is validated on
    /// read (`hops_ipc::pairing::valid_fingerprint`). Also
    /// the join key a frontend uses to correlate this client with its
    /// `authorized_fingerprints` entry (byte-identical to the allowlist key).
    #[serde(default)]
    pub peer_fingerprint: Option<String>,
}

/// Who caused a connection attempt to be raised.
///
/// Both origins used to emit an identical event, so nothing downstream — the UI
/// included — could tell "a peer knocked on my door" from "something asked me to
/// go find them". That distinction is not cosmetic: `Create`, `UpdateFixIps` and
/// `Activate` are all unguarded console verbs, so anything holding the IPC token
/// can make the daemon DIAL an address of its choosing and thereby manufacture a
/// genuine-looking prompt for a fingerprint it picked, at a moment it picked
/// (#61).
///
/// You cannot prove where a keystroke came from. You CAN prove where a prompt
/// came from, because hops caused it — this is that proof, carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptOrigin {
    /// A peer connected to us unsolicited. Nothing local chose this moment.
    Inbound,
    /// We dialled out and the receiver was not trusted. A console verb can cause
    /// this, so it must never be sufficient on its own to grant trust.
    OutboundDial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrontendEvent {
    /// a client was created
    Created(ClientHandle, ClientConfig, ClientState),
    /// no such client
    NoSuchClient(ClientHandle),
    /// state changed
    State(ClientHandle, ClientConfig, ClientState),
    /// the client was deleted
    Deleted(ClientHandle),
    /// new port, reason of failure (if failed)
    PortChanged(u16, Option<String>),
    /// list of all clients, used for initial state synchronization
    Enumerate(Vec<(ClientHandle, ClientConfig, ClientState)>),
    /// an error occured
    Error(String),
    /// capture status
    CaptureStatus(Status),
    /// emulation status
    EmulationStatus(Status),
    /// authorized public key fingerprints have been updated
    AuthorizedUpdated(HashMap<String, String>),
    /// public key fingerprint of this device
    PublicKeyFingerprint(String),
    /// this device's own pairing code (encoded, ready to share out-of-band), or
    /// empty if no shareable LAN address is available. See `pairing::PairingCode`.
    PairingCode(String),
    /// the set of deliberately-revoked fingerprints changed
    RevokedUpdated(HashMap<String, RevokedEntry>),
    /// new device connected
    DeviceConnected {
        addr: SocketAddr,
        fingerprint: String,
    },
    /// incoming device entered the screen
    DeviceEntered {
        fingerprint: String,
        addr: SocketAddr,
        pos: Position,
    },
    /// incoming disconnected
    IncomingDisconnected(SocketAddr),
    /// Machines seen on the local network that are not already configured or
    /// trusted. Replaces the whole list each time rather than diffing, because
    /// mDNS records come and go and a frontend that missed one event would
    /// otherwise show a device that is no longer there.
    ///
    /// NOTHING here is authenticated. `claimed_fingerprint` is an assertion by
    /// whatever is on the LAN, kept for labelling and for spotting a mismatch
    /// against the certificate actually presented. A frontend must never treat
    /// it as identity, and approving one of these still goes through the
    /// ordinary trust prompt (#136).
    Discovered {
        /// Whether hops is actually looking. False when discovery is off in
        /// config, or when mDNS could not start.
        ///
        /// Carried alongside the list rather than inferred from it, because an
        /// EMPTY LIST IS AMBIGUOUS: "switched off", "looking and nothing has
        /// answered yet", and "looking and there is genuinely nothing" are
        /// three different things a user needs told apart, and a frontend that
        /// only sees `[]` renders the same silence for all three (#141).
        active: bool,
        peers: Vec<DiscoveredDevice>,
    },
    /// failed connection attempt (approval for fingerprint required)
    ConnectionAttempt {
        fingerprint: String,
        origin: AttemptOrigin,
        /// The address that answered, when we know it. Present for
        /// `OutboundDial` — the user typed an address and something answered,
        /// and they cannot judge the fingerprint without seeing which address
        /// it came from (#93). `None` inbound, because `ListenEvent::Rejected`
        /// does not carry one (see #83).
        addr: Option<SocketAddr>,
    },
}

/// A machine advertising itself on the local network.
///
/// A suggestion of somewhere to dial, not a device and not an identity. See
/// `FrontendEvent::Discovered`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    /// Advertised instance name. Display only — chosen by the announcer.
    pub label: String,
    /// The fingerprint it CLAIMS. Unauthenticated.
    pub claimed_fingerprint: Option<String>,
    /// Addresses it advertised, all of them.
    pub addrs: Vec<SocketAddr>,
}

/// A fingerprint the user deliberately expelled.
///
/// Kept so a revoked peer is DISTINGUISHABLE from a stranger. Without it,
/// re-approving a machine you just kicked out is indistinguishable from
/// approving a brand-new one — the exact state whose absence has a CVE in
/// matrix-sdk-crypto (RUSTSEC-2024-0434).
///
/// It is NOT an exclusion mechanism and must never be sold as one: a revoked
/// peer can mint a fresh keypair and return as a stranger for free. What it buys
/// is that the SAME key can no longer summon an approval dialog — the peer loses
/// the ability to schedule a security decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedEntry {
    /// what the device was called when trust was withdrawn
    pub label: String,
    /// unix seconds, so the UI can say when without a date dependency
    pub revoked_at: u64,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum FrontendRequest {
    /// activate/deactivate client
    Activate(ClientHandle, bool),
    /// add a new client
    Create,
    /// change the listen port (recreate udp listener)
    ChangePort(u16),
    /// remove a client
    Delete(ClientHandle),
    /// request an enumeration of all clients
    Enumerate(),
    /// resolve dns
    ResolveDns(ClientHandle),
    /// update hostname
    UpdateHostname(ClientHandle, Option<String>),
    /// update port
    UpdatePort(ClientHandle, u16),
    /// update position
    UpdatePosition(ClientHandle, Position),
    /// update spatial layout rect (the drag-to-arrange canvas). Storage only —
    /// coordinate-based crossing is a separate, not-yet-built behavior change.
    UpdateGeometry(ClientHandle, Option<Geometry>),
    /// update fix-ips
    UpdateFixIps(ClientHandle, Vec<IpAddr>),
    /// request reenabling input capture
    EnableCapture,
    /// request reenabling input emulation
    EnableEmulation,
    /// synchronize all state
    Sync,
    /// authorize fingerprint (description, fingerprint)
    AuthorizeKey(String, String),
    /// remove fingerprint (fingerprint)
    RemoveAuthorizedKey(String),
    /// rename an ALREADY-authorized device: (fingerprint, label)
    ///
    /// Renaming used to re-send `AuthorizeKey`, so on this wire a rename and a
    /// trust grant were the same request — a UI could not express "call this
    /// device something else" without also expressing "trust this fingerprint".
    /// This verb deliberately CANNOT grant: an unknown fingerprint is refused,
    /// not inserted (#117-adjacent, Layer 1 of CONSENT-ARCHITECTURE.md).
    SetLabel(String, String),
    // NOTE: there is deliberately NO verb here for the enter hook. It is
    // executed with `sh -c` (src/service.rs), so exposing it on this channel
    // made reaching the frontend socket equivalent to arbitrary command
    // execution. `enter_hook` is a CONFIG-FILE-ONLY field; setting it requires
    // write access to the config directory. See issue #56, and the guard test
    // in src/service.rs that fails if a shell becomes reachable from here again.
    /// save config file
    SaveConfiguration,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum Status {
    #[default]
    Disabled,
    Enabled,
}

impl From<Status> for bool {
    fn from(status: Status) -> Self {
        match status {
            Status::Enabled => true,
            Status::Disabled => false,
        }
    }
}

#[cfg(unix)]
const LAN_MOUSE_SOCKET_NAME: &str = "lan-mouse-socket.sock";

#[derive(Debug, Error)]
pub enum SocketPathError {
    #[error("could not determine $XDG_RUNTIME_DIR: `{0}`")]
    XdgRuntimeDirNotFound(VarError),
    #[error("could not determine $HOME: `{0}`")]
    HomeDirNotFound(VarError),
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn default_socket_path() -> Result<PathBuf, SocketPathError> {
    let xdg_runtime_dir =
        env::var("XDG_RUNTIME_DIR").map_err(SocketPathError::XdgRuntimeDirNotFound)?;
    Ok(Path::new(xdg_runtime_dir.as_str()).join(LAN_MOUSE_SOCKET_NAME))
}

#[cfg(all(unix, target_os = "macos"))]
pub fn default_socket_path() -> Result<PathBuf, SocketPathError> {
    let home = env::var("HOME").map_err(SocketPathError::HomeDirNotFound)?;
    Ok(Path::new(home.as_str())
        .join("Library")
        .join("Caches")
        .join(LAN_MOUSE_SOCKET_NAME))
}

/// The loopback port the daemon listens on where there are no Unix sockets.
///
/// One definition for the listener, both connectors and the front door's
/// probe, so the probe cannot ask a different address from the one the daemon
/// binds.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const TCP_ENDPOINT: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5252));

/// How long the probe waits on a TCP endpoint before concluding nothing is
/// there. A listening daemon completes a loopback handshake at once, and a
/// connect to a closed port is not guaranteed to fail fast, so this bounds
/// what asking costs on a machine with no daemon.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Where a frontend reaches the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonEndpoint {
    /// A Unix domain socket, on macOS and Linux.
    #[cfg(unix)]
    Unix(PathBuf),
    /// A loopback TCP port, on Windows.
    Tcp(SocketAddr),
}

impl Display for DaemonEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "{}", path.display()),
            Self::Tcp(addr) => write!(f, "{addr}"),
        }
    }
}

impl DaemonEndpoint {
    /// The endpoint this platform's daemon listens on: the one
    /// [`AsyncFrontendListener::new`] binds and [`connect()`] and
    /// [`connect_async()`] dial.
    ///
    /// Only the defaults read it. Code that is handed an endpoint, such as
    /// [`AsyncFrontendListener::at`] and [`connect_async_to`], uses that one,
    /// and nothing in the environment can point a frontend elsewhere.
    pub fn of_this_platform() -> Result<Self, SocketPathError> {
        #[cfg(unix)]
        {
            Ok(Self::Unix(default_socket_path()?))
        }
        #[cfg(windows)]
        {
            Ok(Self::Tcp(TCP_ENDPOINT))
        }
    }

    /// Whether something accepts a connection here right now.
    ///
    /// Connects and hangs up without sending anything. The daemon sees a
    /// frontend that closed before presenting its token, and drops it without
    /// logging a warning. A Unix socket whose queue of connections waiting to
    /// be accepted is full has a listener, and answers.
    pub fn answers(&self) -> bool {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => match connect_unix_now(path) {
                Ok(_) => true,
                Err(e) => e.kind() == io::ErrorKind::WouldBlock,
            },
            Self::Tcp(addr) => std::net::TcpStream::connect_timeout(addr, PROBE_TIMEOUT).is_ok(),
        }
    }

    /// Whether a daemon serves frontends here: it takes `token` and sends a
    /// frontend its state, all within `within`.
    ///
    /// Stronger than [`Self::answers`]. A daemon binds its endpoint before it
    /// reads the token, the config and its keys, and one that fails on any of
    /// them exits a moment later, so something answering says little about
    /// whether a daemon is running. A daemon sends state only once its service
    /// loop runs. Hangs up after the first event, which the daemon treats as
    /// an ordinary frontend leaving.
    ///
    /// `within` bounds the whole ask, not each step: whatever is on the
    /// endpoint, sending a byte at a time or never accepting, the answer comes
    /// by then.
    pub fn serves(&self, token: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        let exchange = || -> io::Result<bool> {
            match self {
                #[cfg(unix)]
                Self::Unix(path) => state_follows_token(connect_unix_now(path)?, token, deadline),
                Self::Tcp(addr) => {
                    let stream = std::net::TcpStream::connect_timeout(addr, time_left(deadline)?)?;
                    state_follows_token(stream, token, deadline)
                }
            }
        };
        exchange().unwrap_or(false)
    }
}

/// A connected stream whose reads and writes can be given a timeout.
trait Timed: io::Read + io::Write {
    fn wait_at_most(&self, within: Duration) -> io::Result<()>;
}

impl Timed for std::net::TcpStream {
    fn wait_at_most(&self, within: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(within))?;
        self.set_write_timeout(Some(within))
    }
}

#[cfg(unix)]
impl Timed for std::os::unix::net::UnixStream {
    fn wait_at_most(&self, within: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(within))?;
        self.set_write_timeout(Some(within))
    }
}

/// How much of one line an ask holds before it concludes no daemon is there.
///
/// A daemon's first event lists its clients, a few kilobytes. The limit bounds
/// what something else on the endpoint can make the front door hold while it
/// waits.
const EVENT_LINE_LIMIT: usize = 1 << 20;

/// How long is left until `deadline`; a timeout once nothing is.
fn time_left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(left)
}

/// Present `token` on `stream`, and say whether an event comes back by
/// `deadline`.
///
/// Any whole line of JSON counts, not only a [`FrontendEvent`] this build
/// knows: the daemon may be another version, left running by launchd across
/// an update, and it still serves.
fn state_follows_token(mut stream: impl Timed, token: &str, deadline: Instant) -> io::Result<bool> {
    stream.wait_at_most(time_left(deadline)?)?;
    stream.write_all(format!("{token}\n").as_bytes())?;
    let mut line = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // Every read waits only for what is left. A timeout per read let a
        // peer that sends a byte now and then keep the ask going for good.
        stream.wait_at_most(time_left(deadline)?)?;
        let read = match stream.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(n) => &chunk[..n],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if let Some(end) = read.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&read[..end]);
            return Ok(serde_json::from_slice::<serde_json::Value>(&line).is_ok());
        }
        line.extend_from_slice(read);
        if line.len() > EVENT_LINE_LIMIT {
            return Ok(false);
        }
    }
}

/// Connect to the Unix socket at `path` without waiting for the listener.
///
/// A blocking connect on Linux waits for as long as the listener's queue of
/// connections not yet accepted stays full, as it does beside a process that
/// binds and never accepts. This fails with [`io::ErrorKind::WouldBlock`]
/// instead. The stream it returns blocks.
#[cfg(unix)]
fn connect_unix_now(path: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `sockaddr_un` is plain data, for which all zeroes is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} cannot name a Unix socket", path.display()),
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in addr.sun_path.iter_mut().zip(bytes) {
        *to = libc::c_char::from_ne_bytes([*from]);
    }
    // The path and its terminating zero, which the zeroed address supplies.
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: `socket` takes plain values and returns a new descriptor or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened, and nothing else owns it.
    let stream = std::os::unix::net::UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SAFETY: `fd` is open; F_SETFD takes a plain flag.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    stream.set_nonblocking(true)?;
    // SAFETY: `addr` is a valid `sockaddr_un` of at least `len` bytes, and the
    // descriptor is open.
    let connected = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            len as libc::socklen_t,
        )
    };
    if connected == -1 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod serves_whatever_its_version {
    //! The front door asks whether a daemon serves after it starts one. The
    //! daemon it reaches may be another build, left running across an update,
    //! whose events this build does not know.

    use super::DaemonEndpoint;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::time::{Duration, Instant};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A daemon stand-in on a loopback port that answers one connection with
    /// `reply` once it has read the token, then stays connected until the
    /// asker hangs up, or hangs up itself when `reply` is not a whole line.
    /// Returns its endpoint and whether the token arrived as a line of its own.
    fn replying(reply: &'static str) -> (DaemonEndpoint, std::thread::JoinHandle<bool>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let endpoint = DaemonEndpoint::Tcp(listener.local_addr().expect("its address"));
        let peer = std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return false;
            };
            let mut reader = BufReader::new(stream.try_clone().expect("a second handle"));
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let mut writer = stream;
            let _ = writer.write_all(reply.as_bytes());
            if reply.ends_with('\n') {
                let _ = reader.read_to_end(&mut Vec::new());
            }
            line == format!("{TOKEN}\n")
        });
        (endpoint, peer)
    }

    fn ask(reply: &'static str) -> (bool, bool) {
        let (endpoint, peer) = replying(reply);
        let serves = endpoint.serves(TOKEN, Duration::from_secs(2));
        (serves, peer.join().expect("the stand-in daemon"))
    }

    // LEDGER T41 | class B | 2 bytes over a real socket + 1 return value
    #[test]
    fn any_event_counts_and_anything_else_does_not() {
        assert_eq!(
            (
                ask("{\"AnEventOfALaterBuild\":{\"n\":1}}\n"),
                ask("not json\n"),
                ask("{}"),
            ),
            ((true, true), (false, true), (false, true)),
            "((event unknown to this build), (not JSON), (no whole line before the \
             hang-up)), each as \
             (counted as serving, token sent as a line). A daemon of another build \
             serves all the same; the front door would log it as silent."
        );
    }

    // LEDGER T42 | class B | 1 return value + elapsed time over a real socket
    #[test]
    fn a_peer_that_never_ends_its_line_is_given_up_on_when_the_ask_is_due() {
        const TRICKLES_FOR: Duration = Duration::from_secs(5);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let endpoint = DaemonEndpoint::Tcp(listener.local_addr().expect("its address"));
        // Takes the token, then starts a line of JSON and adds a space to it
        // every 50 ms, never ending it, until the asker hangs up.
        let peer = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let _ = stream.read(&mut [0u8; TOKEN.len() + 1]);
            let began = Instant::now();
            let mut sent = stream.write_all(b"{");
            while sent.is_ok() && began.elapsed() < TRICKLES_FOR {
                std::thread::sleep(Duration::from_millis(50));
                sent = stream.write_all(b" ");
            }
        });

        let within = Duration::from_millis(500);
        let began = Instant::now();
        let serves = endpoint.serves(TOKEN, within);
        let took = began.elapsed();
        let _ = peer.join();
        assert!(
            !serves && took < within + Duration::from_secs(1),
            "asked to answer within {within:?}, `serves` said {serves} after \
             {took:?}. A peer that sends a byte at a time never lets a timeout \
             per read expire, and the front door does not open until it has \
             its answer."
        );
    }

    // LEDGER T48 | class B | 1 return value + elapsed time over a real socket
    #[test]
    fn a_peer_that_floods_one_line_is_given_up_on_once_it_is_past_any_event() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let endpoint = DaemonEndpoint::Tcp(listener.local_addr().expect("its address"));
        // Takes the token, sends one byte more than any event may have and no
        // newline, then waits for the asker to hang up.
        let peer = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.read(&mut [0u8; TOKEN.len() + 1]);
            let mut flood = vec![b' '; super::EVENT_LINE_LIMIT + 1];
            flood[0] = b'[';
            if stream.write_all(&flood).is_ok() {
                let _ = stream.read_to_end(&mut Vec::new());
            }
        });

        let within = Duration::from_secs(4);
        let began = Instant::now();
        let serves = endpoint.serves(TOKEN, within);
        let took = began.elapsed();
        let _ = peer.join();
        assert!(
            !serves && took < within / 2,
            "`serves` said {serves} after {took:?} of {within:?}, for a peer that \
             sent more of one line than any event has. Reading on holds all of it \
             in memory for as long as the ask lasts."
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod a_full_accept_queue {
    //! On Linux a blocking connect to a Unix socket waits for as long as the
    //! listener's queue of connections not yet accepted is full.

    use super::DaemonEndpoint;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // LEDGER T43 | class B | 1 return value + elapsed time over a real socket
    #[test]
    fn a_listener_that_never_accepts_neither_holds_up_the_asker_nor_serves() {
        let path = PathBuf::from(format!("/tmp/h-queue-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("a unix listener");
        // SAFETY: plain values on an open socket. Linux takes a second
        // `listen` as a new queue length; with 0, one waiting connection
        // fills the queue.
        let listened = unsafe { libc::listen(listener.as_raw_fd(), 0) };
        let waiting = UnixStream::connect(&path).expect("a connection nothing accepts");

        let endpoint = DaemonEndpoint::Unix(path.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let began = Instant::now();
            let answers = endpoint.answers();
            let serves = endpoint.serves(TOKEN, Duration::from_millis(300));
            let _ = tx.send((answers, serves, began.elapsed()));
        });
        let got = rx.recv_timeout(Duration::from_secs(5));
        drop((waiting, listener));
        let _ = std::fs::remove_file(&path);

        assert_eq!(listened, 0, "the stand-in could not shorten its queue");
        let Ok((answers, serves, took)) = got else {
            panic!(
                "asking a listener whose queue is full had not returned after 5 s. \
                 The front door asks before it opens the app, and would not open."
            );
        };
        assert!(
            (answers, serves) == (true, false) && took < Duration::from_secs(1),
            "(answers, serves) = {:?} after {took:?}. Something listens there, so \
             the front door must not start a daemon beside it, and it takes the \
             token from no one, so it does not serve.",
            (answers, serves)
        );
    }
}
