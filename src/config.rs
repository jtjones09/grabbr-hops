use crate::capture_test::TestCaptureArgs;
use crate::emulation_test::TestEmulationArgs;
use clap::{Parser, Subcommand, ValueEnum};
use notify::event::ModifyKind;
use notify::{EventKind, RecommendedWatcher, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env::{self, VarError};
use std::fmt::Display;
use std::fs::{self, File};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::{collections::HashSet, io};
use thiserror::Error;
use toml_edit::{self, DocumentMut};

use hops_cli::CliArgs;
use hops_ipc::{DEFAULT_PORT, Position, RevokedEntry};

use input_event::scancode::{
    self,
    Linux::{KeyLeftAlt, KeyLeftCtrl, KeyLeftMeta, KeyLeftShift},
};

/// Local build's 8-byte ASCII short commit hash, suitable for use
/// in [`hops_proto::ProtoEvent::Hello`]. Set by `build.rs` (via the `git` CLI —
/// no libgit2). Pads with `'?'` if it's an unexpected length so the field is
/// always well-formed on the wire.
pub fn local_commit() -> [u8; 8] {
    let bytes = env!("HOPS_SHORT_COMMIT").as_bytes();
    let mut out = [b'?'; 8];
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Capability bits this build advertises in the [`hops_proto::ProtoEvent::Capability`]
/// handshake — the OR of every optional feature we actually implement AND choose
/// to negotiate right now. A peer that sees `ABSOLUTE_MOTION` emits absolute
/// motion to us (which PR-3 reconstructs), and our sender emits it to any peer
/// that advertises it back.
///
/// `ABSOLUTE_MOTION` is now **on by default** — validated on the real rig
/// (a full-workday soak: near-native feel, ratio parity with the relative
/// path, zero regressions). Set `HOPS_ABSOLUTE_MOTION=0` (or `off`) to disable
/// it for A/B comparison or debugging; the peer then never sees the bit and we
/// fall back to the relative path. Advertising the bit is an honest opt-in:
/// the peer only emits absolute motion once it observes we support it.
pub fn local_caps() -> u32 {
    let disabled = std::env::var("HOPS_ABSOLUTE_MOTION")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("off"))
        .unwrap_or(false);
    if disabled {
        0
    } else {
        hops_proto::caps::ABSOLUTE_MOTION
    }
}

/// `--version` string: package version + short git commit (both compile-time).
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("HOPS_SHORT_COMMIT"),
    ")"
);

const CONFIG_FILE_NAME: &str = "config.toml";
const CERT_FILE_NAME: &str = "lan-mouse.pem";

fn default_path() -> Result<PathBuf, VarError> {
    #[cfg(unix)]
    let default_path = {
        let xdg_config_home =
            env::var("XDG_CONFIG_HOME").unwrap_or(format!("{}/.config", env::var("HOME")?));
        format!("{xdg_config_home}/lan-mouse/")
    };

    #[cfg(not(unix))]
    let default_path = {
        let app_data =
            env::var("LOCALAPPDATA").unwrap_or(format!("{}/.config", env::var("USERPROFILE")?));
        format!("{app_data}\\lan-mouse\\")
    };
    Ok(PathBuf::from(default_path))
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
struct ConfigToml {
    capture_backend: Option<CaptureBackend>,
    emulation_backend: Option<EmulationBackend>,
    port: Option<u16>,
    release_bind: Option<Vec<scancode::Linux>>,
    cert_path: Option<PathBuf>,
    clients: Option<Vec<TomlClient>>,
    authorized_fingerprints: Option<HashMap<String, String>>,
    /// Fingerprints the user expelled. Persisted so revocation survives a
    /// restart — otherwise a revoked peer is a stranger again on next boot and
    /// can raise the approval prompt exactly as before.
    #[serde(default)]
    revoked_fingerprints: Option<HashMap<String, RevokedEntry>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct TomlClient {
    hostname: Option<String>,
    host_name: Option<String>,
    ips: Option<Vec<IpAddr>>,
    port: Option<u16>,
    position: Option<Position>,
    activate_on_startup: Option<bool>,
    enter_hook: Option<String>,
    /// Leaf-cert fingerprint of this peer, learned at the first handshake and
    /// persisted so the unified device view can join this client to its
    /// `[authorized_fingerprints]` entry from a COLD START — without it every
    /// device renders as two cards until it happens to connect. It also makes
    /// the fail-closed dial pin survive a restart. Not new trust: the same
    /// fingerprint must already be in the allowlist for a dial to succeed.
    #[serde(default)]
    fingerprint: Option<String>,
}

impl ConfigToml {
    fn new(path: &Path) -> Result<ConfigToml, ConfigError> {
        let config = fs::read_to_string(path)?;
        Ok(toml_edit::de::from_str::<_>(&config)?)
    }
}

#[derive(Parser, Debug)]
#[command(author, version = LONG_VERSION, about, long_about = None)]
struct Args {
    /// the listen port for lan-mouse
    #[arg(short, long)]
    port: Option<u16>,

    /// non-default config file location
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// capture backend override
    #[arg(long)]
    capture_backend: Option<CaptureBackend>,

    /// emulation backend override
    #[arg(long)]
    emulation_backend: Option<EmulationBackend>,

    /// path to non-default certificate location
    #[arg(long)]
    cert_path: Option<PathBuf>,

    /// subcommands
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// test input emulation
    TestEmulation(TestEmulationArgs),
    /// test input capture
    TestCapture(TestCaptureArgs),
    /// hops commandline interface
    Cli(CliArgs),
    /// run in daemon mode (the receiver; normally started by launchd)
    Daemon,
    /// open the graphical interface (attaches to the daemon)
    Gui {
        /// start hidden in the menu bar / system tray — no window until the
        /// tray icon is clicked. Used by the login-autostart item so logging in
        /// shows the icon, not a window.
        #[arg(long)]
        hidden: bool,
    },
    /// open the terminal interface (attaches to the daemon)
    Tui,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
pub enum CaptureBackend {
    #[cfg(libei_capture)]
    #[serde(rename = "input-capture-portal")]
    InputCapturePortal,
    #[cfg(layer_shell_capture)]
    #[serde(rename = "layer-shell")]
    LayerShell,
    #[cfg(x11_capture)]
    #[serde(rename = "x11")]
    X11,
    #[cfg(windows)]
    #[serde(rename = "windows")]
    Windows,
    #[cfg(target_os = "macos")]
    #[serde(rename = "macos")]
    MacOs,
    #[serde(rename = "dummy")]
    Dummy,
}

impl Display for CaptureBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(libei_capture)]
            CaptureBackend::InputCapturePortal => write!(f, "input-capture-portal"),
            #[cfg(layer_shell_capture)]
            CaptureBackend::LayerShell => write!(f, "layer-shell"),
            #[cfg(x11_capture)]
            CaptureBackend::X11 => write!(f, "X11"),
            #[cfg(windows)]
            CaptureBackend::Windows => write!(f, "windows"),
            #[cfg(target_os = "macos")]
            CaptureBackend::MacOs => write!(f, "MacOS"),
            CaptureBackend::Dummy => write!(f, "dummy"),
        }
    }
}

impl From<CaptureBackend> for input_capture::Backend {
    fn from(backend: CaptureBackend) -> Self {
        match backend {
            #[cfg(libei_capture)]
            CaptureBackend::InputCapturePortal => Self::InputCapturePortal,
            #[cfg(layer_shell_capture)]
            CaptureBackend::LayerShell => Self::LayerShell,
            #[cfg(x11_capture)]
            CaptureBackend::X11 => Self::X11,
            #[cfg(windows)]
            CaptureBackend::Windows => Self::Windows,
            #[cfg(target_os = "macos")]
            CaptureBackend::MacOs => Self::MacOs,
            CaptureBackend::Dummy => Self::Dummy,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
pub enum EmulationBackend {
    #[cfg(wlroots_emulation)]
    #[serde(rename = "wlroots")]
    Wlroots,
    #[cfg(libei_emulation)]
    #[serde(rename = "libei")]
    Libei,
    #[cfg(rdp_emulation)]
    #[serde(rename = "xdp")]
    Xdp,
    #[cfg(x11_emulation)]
    #[serde(rename = "x11")]
    X11,
    #[cfg(windows)]
    #[serde(rename = "windows")]
    Windows,
    #[cfg(target_os = "macos")]
    #[serde(rename = "macos")]
    MacOs,
    #[serde(rename = "dummy")]
    Dummy,
}

impl From<EmulationBackend> for input_emulation::Backend {
    fn from(backend: EmulationBackend) -> Self {
        match backend {
            #[cfg(wlroots_emulation)]
            EmulationBackend::Wlroots => Self::Wlroots,
            #[cfg(libei_emulation)]
            EmulationBackend::Libei => Self::Libei,
            #[cfg(rdp_emulation)]
            EmulationBackend::Xdp => Self::Xdp,
            #[cfg(x11_emulation)]
            EmulationBackend::X11 => Self::X11,
            #[cfg(windows)]
            EmulationBackend::Windows => Self::Windows,
            #[cfg(target_os = "macos")]
            EmulationBackend::MacOs => Self::MacOs,
            EmulationBackend::Dummy => Self::Dummy,
        }
    }
}

impl Display for EmulationBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(wlroots_emulation)]
            EmulationBackend::Wlroots => write!(f, "wlroots"),
            #[cfg(libei_emulation)]
            EmulationBackend::Libei => write!(f, "libei"),
            #[cfg(rdp_emulation)]
            EmulationBackend::Xdp => write!(f, "xdg-desktop-portal"),
            #[cfg(x11_emulation)]
            EmulationBackend::X11 => write!(f, "X11"),
            #[cfg(windows)]
            EmulationBackend::Windows => write!(f, "windows"),
            #[cfg(target_os = "macos")]
            EmulationBackend::MacOs => write!(f, "macos"),
            EmulationBackend::Dummy => write!(f, "dummy"),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    /// command line arguments
    args: Args,
    /// path to the certificate file used
    cert_path: PathBuf,
    /// path to the config file used
    config_path: PathBuf,
    /// path to config directory (parent of above)
    config_dir: PathBuf,
    /// the (optional) toml config and it's path
    config_toml: Option<ConfigToml>,
    // filesystem watcher
    watcher: notify::RecommendedWatcher,
    // channel for filesystem events
    watch_rx: tokio::sync::mpsc::Receiver<Result<notify::Event, notify::Error>>,
}

pub struct ConfigClient {
    pub ips: HashSet<IpAddr>,
    pub hostname: Option<String>,
    pub port: u16,
    pub pos: Position,
    pub active: bool,
    pub enter_hook: Option<String>,
    pub fingerprint: Option<String>,
}

impl From<TomlClient> for ConfigClient {
    fn from(toml: TomlClient) -> Self {
        let active = toml.activate_on_startup.unwrap_or(false);
        let enter_hook = toml.enter_hook;
        let hostname = toml.hostname;
        let ips = HashSet::from_iter(toml.ips.into_iter().flatten());
        let port = toml.port.unwrap_or(DEFAULT_PORT);
        let pos = toml.position.unwrap_or_default();
        // reject a malformed value rather than letting it reach the pin
        let fingerprint = toml
            .fingerprint
            .filter(|fp| hops_ipc::pairing::valid_fingerprint(fp));
        Self {
            ips,
            hostname,
            port,
            pos,
            active,
            enter_hook,
            fingerprint,
        }
    }
}

impl From<ConfigClient> for TomlClient {
    fn from(client: ConfigClient) -> Self {
        let hostname = client.hostname;
        let host_name = None;
        let mut ips = client.ips.into_iter().collect::<Vec<_>>();
        ips.sort();
        let ips = Some(ips);
        let port = if client.port == DEFAULT_PORT {
            None
        } else {
            Some(client.port)
        };
        let position = Some(client.pos);
        let activate_on_startup = if client.active { Some(true) } else { None };
        let enter_hook = client.enter_hook;
        let fingerprint = client.fingerprint;
        Self {
            hostname,
            host_name,
            ips,
            port,
            position,
            activate_on_startup,
            enter_hook,
            fingerprint,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Toml(#[from] toml_edit::de::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Var(#[from] VarError),
    #[error(transparent)]
    Watcher(#[from] notify::Error),
}

const DEFAULT_RELEASE_KEYS: [scancode::Linux; 4] =
    [KeyLeftCtrl, KeyLeftShift, KeyLeftMeta, KeyLeftAlt];

/// Create (or truncate) a file that is private to the owner from the moment it
/// exists. Never create-then-chmod: that leaves a window in which the file is
/// world-readable, and the file this is used for holds `[authorized_fingerprints]`
/// — the list of keys allowed to take this machine's keyboard and mouse.
///
/// Same pattern, and the same reason, as `hops_ipc::token::write_private`.
fn create_private(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        File::create(path)
    }
}

/// Tighten an existing config directory and config file that were created before
/// this was enforced.
///
/// Measured on 2026-08-30: `~/.config/lan-mouse` was `drwxr-xr-x` and
/// `config.toml` was `-rw-r--r--`, while the private key was `0400` and the IPC
/// token `0600`. The most permissive file in the directory was the one that
/// grants keyboard control. New files are created correctly by `create_private`;
/// this repairs the installs that already exist, because a fix that only applies
/// going forward leaves every current user exposed.
///
/// Best-effort by design: a failure here must not stop the daemon from starting.
#[cfg(unix)]
fn harden_existing(config_dir: &Path, config_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let tighten = |p: &Path, want: u32| {
        let Ok(meta) = fs::metadata(p) else { return };
        let mode = meta.permissions().mode() & 0o777;
        if mode & !want != 0 {
            let mut perm = meta.permissions();
            perm.set_mode(want);
            match fs::set_permissions(p, perm) {
                Ok(()) => log::info!("tightened {} from {:o} to {:o}", p.display(), mode, want),
                Err(e) => log::warn!("could not tighten {}: {e}", p.display()),
            }
        }
    };
    tighten(config_dir, 0o700);
    tighten(config_path, 0o600);
}

#[cfg(not(unix))]
fn harden_existing(_config_dir: &Path, _config_path: &Path) {}

/// Subtract the tombstones from the allowlist. Pure, so the rule can be tested
/// without standing up a `Config`; see [`Config::effective_allowlist`], which is
/// the only caller and the only door.
///
/// Both maps arrive lowercased by their readers. That is load-bearing: when only
/// the authorized table was normalised, the two could name the same peer in two
/// spellings and never match (issue #67).
/// Replace a file's contents atomically: write a sibling temp, flush it, rename.
///
/// The trust store used to be opened with `truncate(true)` and only then written,
/// so any kill inside that window — a launchd `KeepAlive` bounce, power loss,
/// OOM — left a partial file. A partial TOML is an unparseable TOML, which used
/// to mean the next start came up with an empty allowlist and an empty revocation
/// table (issue #69).
///
/// `rename(2)` is atomic within a filesystem and the temp file is a sibling, so it
/// is always the same one. A reader sees the whole old file or the whole new one,
/// never a truncated one. The temp inherits [`create_private`]'s `0600`, so the
/// contents are never briefly world-readable either.
fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), io::Error> {
    let tmp = path.with_extension("toml.tmp");
    {
        let mut f = create_private(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // Durability of the rename itself. Without this the directory entry can still
    // be lost to a crash even though the file's contents were synced.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

fn subtract_revoked(
    mut authorized: HashMap<String, String>,
    revoked: &HashMap<String, RevokedEntry>,
) -> (HashMap<String, String>, Vec<String>) {
    let mut refused: Vec<String> = revoked
        .keys()
        .filter(|fp| authorized.contains_key(*fp))
        .cloned()
        .collect();
    refused.sort();
    for fp in &refused {
        authorized.remove(fp);
    }
    (authorized, refused)
}

impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        let args = Args::parse();

        // --config <file> overrules default location
        let config_path = args
            .config
            .clone()
            .unwrap_or(default_path()?.join(CONFIG_FILE_NAME));
        let config_dir = config_path
            .parent()
            .expect("config directory")
            .to_path_buf();

        // Ensure the config directory exists and write a default config file
        // if none is present. Runs on every Config::new(), regardless of which
        // entry path (GUI main, spawned daemon, CLI, test commands) we're on,
        // so a fresh Mac never hits "No such file or directory" on config.toml
        // and notify::Watcher (which requires the dir to exist on macOS
        // FSEvents and some Linux backends) has a concrete path to watch.
        fs::create_dir_all(&config_dir)?;
        if !config_path.exists() {
            let default_toml = toml_edit::ser::to_string_pretty(&ConfigToml::default())
                .expect("default ConfigToml serialization cannot fail");
            let mut f = create_private(&config_path)?;
            f.write_all(default_toml.as_bytes())?;
        }
        // Repair installs created before the modes above were enforced.
        harden_existing(&config_dir, &config_path);

        // A config file that EXISTS but does not parse is a hard error, not an
        // absent one. Treating the two the same came in from upstream and meant a
        // single type error — `port = "4242"` — brought the daemon up with an
        // empty allowlist AND an empty revocation table, and the first
        // `save_config()` after that persisted the emptiness. The user was left
        // believing both that hops had forgotten their devices and that
        // revocations they performed were still in force. Neither was true.
        //
        // An absent file legitimately means defaults. A corrupt one never does.
        let config_toml = match ConfigToml::new(&config_path) {
            Err(e) => {
                log::error!(
                    "{config_path:?} exists but could not be parsed: {e}\n\
                     Refusing to start. Continuing would discard every authorized \
                     device AND every revocation on the next save. Fix the file, or \
                     move it aside to start fresh."
                );
                return Err(e);
            }
            Ok(c) => Some(c),
        };

        // --cert-path <file> overrules default location
        let cert_path = args
            .cert_path
            .clone()
            .or(config_toml.as_ref().and_then(|c| c.cert_path.clone()))
            .unwrap_or(default_path()?.join(CERT_FILE_NAME));

        let (tx, watch_rx) = tokio::sync::mpsc::channel(16);
        let watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            notify::Config::default(),
        )?;
        let mut config = Config {
            args,
            cert_path,
            config_path,
            config_dir,
            config_toml,
            watcher,
            watch_rx,
        };
        config.watch()?;
        Ok(config)
    }

    fn watch(&mut self) -> Result<(), notify::Error> {
        self.watcher
            .watch(&self.config_dir, notify::RecursiveMode::NonRecursive)?;
        Ok(())
    }

    fn unwatch(&mut self) -> Result<(), notify::Error> {
        self.watcher.unwatch(&self.config_dir)?;
        Ok(())
    }

    pub async fn changed(&mut self) -> Result<(), notify::Error> {
        loop {
            let event = self.watch_rx.recv().await.expect("channel closed");
            let event = event.expect("filesystem event");
            if event.paths.contains(&self.config_path)
                && matches!(
                    event.kind,
                    EventKind::Create(_)
                        | EventKind::Modify(ModifyKind::Data(_))
                        | EventKind::Remove(_)
                )
                && self.read_from_disk()?
            {
                return Ok(());
            }
        }
    }

    /// the command to run
    pub fn command(&self) -> Option<Command> {
        self.args.command.clone()
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// fingerprints the user deliberately revoked
    ///
    /// Keys are lowercased on read for exactly the same reason
    /// [`Self::authorized_fingerprints`] does it: the two tables are compared
    /// against each other, and normalising only one of them is what let an
    /// expelled fingerprint be re-authorized in uppercase (issue #67).
    pub fn revoked_fingerprints(&self) -> HashMap<String, RevokedEntry> {
        self.config_toml
            .as_ref()
            .and_then(|c| c.revoked_fingerprints.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect()
    }

    /// The allowlist the daemon may actually act on: everything authorized,
    /// **minus** everything revoked. Returns the refused fingerprints so the
    /// caller can say so.
    ///
    /// This is the ONLY door. Revocation outranks the allowlist, and before
    /// this existed that rule was enforced on the config-reload path and not on
    /// the startup path — so a revoked fingerprint put back into
    /// `[authorized_fingerprints]` (a dotfiles restore, a Time Machine
    /// rollback, a hand-edit) was refused while the daemon ran and silently
    /// honoured on the next boot. Reboot is the most common state transition in
    /// the system and it was the one that failed open (issue #66).
    pub fn effective_allowlist(&self) -> (HashMap<String, String>, Vec<String>) {
        subtract_revoked(self.authorized_fingerprints(), &self.revoked_fingerprints())
    }

    pub fn set_revoked_fingerprints(&mut self, revoked: HashMap<String, RevokedEntry>) {
        self.config_toml
            .get_or_insert_with(Default::default)
            .revoked_fingerprints = Some(revoked);
    }

    /// public key fingerprints authorized for connection
    pub fn authorized_fingerprints(&self) -> HashMap<String, String> {
        self.config_toml
            .as_ref()
            .and_then(|c| c.authorized_fingerprints.clone())
            .unwrap_or_default()
            .into_iter()
            // Normalize keys to lowercase: computed leaf-cert fingerprints are
            // lowercase `aa:bb:..`, so an upper/mixed-case fingerprint in a
            // hand-edited config would otherwise silently never match its peer.
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect()
    }

    /// path to certificate
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// optional input-capture backend override
    pub fn capture_backend(&self) -> Option<CaptureBackend> {
        self.args
            .capture_backend
            .or(self.config_toml.as_ref().and_then(|c| c.capture_backend))
    }

    /// optional input-emulation backend override
    pub fn emulation_backend(&self) -> Option<EmulationBackend> {
        self.args
            .emulation_backend
            .or(self.config_toml.as_ref().and_then(|c| c.emulation_backend))
    }

    /// the port to use (initially)
    pub fn port(&self) -> u16 {
        self.args
            .port
            .or(self.config_toml.as_ref().and_then(|c| c.port))
            .unwrap_or(DEFAULT_PORT)
    }

    /// list of configured clients
    pub fn clients(&self) -> Vec<ConfigClient> {
        self.config_toml
            .as_ref()
            .map(|c| c.clients.clone())
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .map(From::<TomlClient>::from)
            .collect()
    }

    /// release bind for returning control to the host
    pub fn release_bind(&self) -> Vec<scancode::Linux> {
        self.config_toml
            .as_ref()
            .and_then(|c| c.release_bind.clone())
            .unwrap_or(Vec::from_iter(DEFAULT_RELEASE_KEYS.iter().cloned()))
    }

    /// set configured clients
    ///
    /// Always persists the passed list — including an empty one. The caller
    /// (`save_config`) hands us the authoritative current set, so an empty list
    /// means "no clients" and must be written through; the old early-return on
    /// empty was the "phantom no-hostname client regenerates" bug (deleting your
    /// only client couldn't persist, so the stale entry reloaded). Mirrors
    /// `set_authorized_keys`, which correctly has no such guard.
    pub fn set_clients(&mut self, clients: Vec<ConfigClient>) {
        if self.config_toml.is_none() {
            self.config_toml = Some(Default::default());
        }
        self.config_toml.as_mut().expect("config").clients =
            Some(clients.into_iter().map(|c| c.into()).collect::<Vec<_>>());
    }

    /// set authorized keys
    pub fn set_authorized_keys(&mut self, fingerprints: HashMap<String, String>) {
        if self.config_toml.is_none() {
            self.config_toml = Some(Default::default());
        }
        self.config_toml
            .as_mut()
            .expect("config")
            .authorized_fingerprints = Some(fingerprints);
    }

    pub fn read_from_disk(&mut self) -> Result<bool, io::Error> {
        log::info!("reading config from {:?}", &self.config_path);

        let current_config = fs::read_to_string(&self.config_path)?;
        let current_config = match current_config.parse::<DocumentMut>() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("{:?} {e}", self.config_path());
                return Ok(false);
            }
        };
        let mut changed = false;
        match toml_edit::de::from_document::<ConfigToml>(current_config) {
            Ok(current_config) => {
                changed = self
                    .config_toml
                    .as_ref()
                    .is_none_or(|c| c != &current_config);
                self.config_toml.replace(current_config);
            }
            Err(e) => log::warn!("{:?} {e}", self.config_path()),
        };
        if changed {
            log::info!("config changed");
        } else {
            log::info!("config unchanged");
        }
        Ok(changed)
    }

    pub fn write_back(&mut self) -> Result<(), io::Error> {
        log::info!("writing config to {:?}", &self.config_path);
        /* the new config */
        // Never serialise `unwrap_or_default()`. If there is no parsed config in
        // memory, writing is the one thing this must not do — that is how a parse
        // failure became a zero-byte trust store. Unreachable since a corrupt
        // config is now fatal at startup, and kept as the second gate anyway.
        let Some(new_config) = self.config_toml.clone() else {
            log::error!(
                "refusing to write {:?}: there is no parsed config in memory, and \
                 writing defaults here would erase the trust store",
                self.config_path
            );
            return Ok(());
        };
        let new_config = toml_edit::ser::to_string_pretty(&new_config).expect("config");

        /*
         * TODO merge with current config file to preserve comments
         * => eventually we might want to split this up into clients configured
         * via the config file and clients managed through the GUI / frontend.
         * The latter should be saved to $XDG_DATA_HOME instead of $XDG_CONFIG_HOME,
         * and clients configured through .config could be made permanent.
         * For now we just override the config file.
         */

        // Bracket the write. EVERY exit between unwatch and watch must re-arm,
        // and the way to guarantee that is to have exactly one exit — not to
        // remember a `self.watch()` before each `return`. #85/#90 were filed
        // because a failed write left the watcher dead for the life of the
        // process ("4 reloads before, 0 after"), and the fix at the time added
        // the re-arm to the write-error path only. The `?` on create_dir_all
        // above it still returned early with the watcher off.
        let _ = self.unwatch();
        let result = self.write_config_file(&new_config);
        let _ = self.watch();
        result
    }

    /// The actual write. Called only between `unwatch` and `watch`, so it is
    /// free to use `?` — its caller re-arms on every path.
    fn write_config_file(&mut self, new_config: &str) -> Result<(), io::Error> {
        /* write new config to file */
        if let Some(p) = self.config_path().parent() {
            fs::create_dir_all(p)?;
        }
        // Write to a sibling temp file, flush it, then RENAME over the real one.
        // The previous code opened the trust store with `truncate(true)` and only
        // then wrote it, so any kill inside that window — a launchd KeepAlive
        // bounce, power loss, OOM — left a partial file on disk. A partial TOML
        // is an unparseable TOML, which used to mean the next start came up with
        // an empty allowlist and an empty revocation table.
        //
        // rename(2) is atomic within a filesystem, and the temp file is a sibling
        // so it is always the same one. A reader sees either the whole old file
        // or the whole new one, never a truncated one.
        write_atomically(self.config_path(), new_config.as_bytes())
    }
}

#[cfg(all(test, unix))]
mod permission_tests {
    //! The trust store must not be world-readable.
    //!
    //! `config.toml` holds `[authorized_fingerprints]` — the keys allowed to take
    //! this machine's keyboard and mouse. Before 2026-08-30 it was written with a
    //! bare `File::create`, landing at umask (0644 on the developer's own Mac)
    //! while the private key was 0400 and the IPC token 0600.

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(p: &Path) -> u32 {
        fs::metadata(p).expect("exists").permissions().mode() & 0o777
    }

    fn tmpdir(name: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hops-perm-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn a_new_config_file_is_owner_only() {
        let d = tmpdir("new");
        let p = d.join("config.toml");
        let mut f = create_private(&p).expect("create");
        f.write_all(b"[authorized_fingerprints]\n").expect("write");
        drop(f);
        assert_eq!(
            mode_of(&p),
            0o600,
            "the trust store must be 0600 from the moment it exists"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn create_private_tightens_a_world_readable_file() {
        // The create-then-chmod window this exists to avoid: prove that even when
        // a permissive file is already there, reopening it lands owner-only.
        let d = tmpdir("existing");
        let p = d.join("config.toml");
        fs::write(&p, b"old").expect("seed");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(mode_of(&p), 0o644, "precondition");

        let mut f = create_private(&p).expect("create");
        f.write_all(b"new").expect("write");
        drop(f);
        harden_existing(&d, &p);

        assert_eq!(
            mode_of(&p),
            0o600,
            "an existing 0644 trust store must be repaired"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn harden_existing_repairs_a_world_readable_install() {
        let d = tmpdir("repair");
        let p = d.join("config.toml");
        fs::write(&p, b"[authorized_fingerprints]\n").expect("seed");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).expect("chmod dir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).expect("chmod file");
        assert_eq!((mode_of(&d), mode_of(&p)), (0o755, 0o644), "precondition");

        harden_existing(&d, &p);

        assert_eq!(mode_of(&d), 0o700, "config dir must end up owner-only");
        assert_eq!(mode_of(&p), 0o600, "trust store must end up owner-only");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn harden_existing_does_not_loosen_a_stricter_install() {
        let d = tmpdir("strict");
        let p = d.join("config.toml");
        fs::write(&p, b"x").expect("seed");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).expect("chmod");
        harden_existing(&d, &p);
        assert_eq!(
            mode_of(&p),
            0o400,
            "must never widen an already-stricter mode"
        );
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod effective_allowlist_tests {
    //! Revocation outranks the allowlist, at EVERY door.
    //!
    //! Before 2026-08-31 the subtraction happened on the config-reload path and
    //! not at startup, so a revoked fingerprint restored into
    //! `[authorized_fingerprints]` was refused while the daemon ran and silently
    //! honoured on the next boot (issue #66). And because only the authorized
    //! table was lowercased on read, the two tables could name the same peer in
    //! two spellings and never match (issue #67).

    use super::*;

    const A: &str = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:\
10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";

    /// Mirrors what `Config::authorized_fingerprints` does on read.
    fn allow(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_string()))
            .collect()
    }

    /// Mirrors what `Config::revoked_fingerprints` does on read.
    fn revoked(fps: &[&str]) -> HashMap<String, RevokedEntry> {
        fps.iter()
            .map(|k| {
                (
                    k.to_lowercase(),
                    RevokedEntry {
                        label: "expelled".into(),
                        revoked_at: 0,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn a_revoked_fingerprint_is_not_in_the_effective_allowlist() {
        let (a, refused) = subtract_revoked(allow(&[(A, "old-thinkpad")]), &revoked(&[A]));
        assert!(
            a.is_empty(),
            "a fingerprint in BOTH tables must not be trusted at startup"
        );
        assert_eq!(
            refused,
            vec![A.to_string()],
            "and the refusal must be reportable"
        );
    }

    #[test]
    fn case_does_not_launder_a_tombstone() {
        // The exact shape of issue #67: expelled in lowercase, re-added upper.
        let (a, refused) =
            subtract_revoked(allow(&[(&A.to_uppercase(), "attacker")]), &revoked(&[A]));
        assert!(
            a.is_empty(),
            "uppercasing a revoked fingerprint must not resurrect it"
        );
        assert_eq!(refused, vec![A.to_string()]);
    }

    #[test]
    fn a_tombstone_written_in_uppercase_still_bites() {
        let (a, _) = subtract_revoked(allow(&[(A, "attacker")]), &revoked(&[&A.to_uppercase()]));
        assert!(
            a.is_empty(),
            "revoked_fingerprints must lowercase on read too"
        );
    }

    #[test]
    fn an_unrevoked_fingerprint_survives() {
        let (a, refused) = subtract_revoked(allow(&[(A, "laptop")]), &revoked(&[]));
        assert_eq!(a.len(), 1, "the ordinary case must still work");
        assert!(refused.is_empty());
    }
}

#[cfg(test)]
mod fail_closed_tests {
    //! A corrupt config must never become an empty trust store.
    //!
    //! Before 2026-08-31, `Config::new` treated a file that existed but did not
    //! parse exactly like an absent one — logged two `warn` lines and continued
    //! with `None`. The daemon came up with an empty allowlist AND an empty
    //! revocation table, and the first `save_config()` persisted that as a
    //! zero-byte file. The user was left believing both that hops had forgotten
    //! their devices and that revocations they had performed were still in
    //! force. Neither was true (issue #69).

    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hops-failclosed-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn a_corrupt_config_is_a_hard_error_not_an_empty_one() {
        let d = tmpdir("parse");
        let p = d.join("config.toml");
        // The exact shape from the issue: a type error, not a syntax error.
        fs::write(&p, b"port = \"4242\"\n").expect("seed");
        let err = ConfigToml::new(&p).expect_err("a type error must not parse");
        assert!(
            format!("{err}").contains("4242") || format!("{err}").contains("invalid type"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn config_new_propagates_a_parse_failure_rather_than_swallowing_it() {
        // Structural: no runtime test can construct a `Config` here (it parses
        // argv and installs a watcher), and the property is about which arm the
        // parse failure takes.
        let src = include_str!("config.rs");
        let start = src
            .find("let config_toml = match ConfigToml::new(&config_path)")
            .expect("the parse site must exist; if it moved, update this guard");
        let arm = &src[start..start + 900];
        let err_arm = arm.split("Err(e) =>").nth(1).expect("an Err arm");
        let err_arm = &err_arm[..err_arm.find("Ok(c)").unwrap_or(err_arm.len())];
        assert!(
            err_arm.contains("return Err"),
            "a config that exists but does not parse must abort startup. Falling \
             through to `None` is how a typo erased the trust store — issue #69."
        );
        assert!(
            !err_arm.contains("None"),
            "the parse failure arm must not yield `None`: that is indistinguishable \
             from an absent config, and an absent config legitimately means defaults."
        );
    }

    #[test]
    fn write_back_refuses_to_serialise_a_missing_config() {
        let src = include_str!("config.rs");
        let start = src
            .find("pub fn write_back(")
            .expect("write_back must exist; if it was renamed, update this guard");
        let rest = &src[start..];
        let end = rest[1..]
            .find("\n    pub fn ")
            .or_else(|| rest[1..].find("\n    fn "))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        // Strip comments: this guard names the very call it forbids, and the
        // function's own doc comment explains why it is forbidden.
        let body: String = rest[..end]
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !body.contains("unwrap_or_default()"),
            "write_back must never serialise a default config. If there is no parsed \
             config in memory, writing is the one thing it must not do — that is how \
             a parse failure became a zero-byte trust store."
        );
    }

    #[test]
    fn the_write_is_atomic_and_leaves_no_debris() {
        let d = tmpdir("atomic");
        let p = d.join("config.toml");
        fs::write(&p, b"old contents that must be replaced whole").expect("seed");

        let new = b"[authorized_fingerprints]\n\"aa:bb\" = \"laptop\"\n";
        write_atomically(&p, new).expect("write");

        assert_eq!(
            fs::read(&p).expect("read"),
            new,
            "the target must be replaced whole"
        );
        let leftovers: Vec<_> = fs::read_dir(&d)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the temp file must not survive a successful write: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn the_replacement_is_owner_only_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        let p = d.join("config.toml");
        fs::write(&p, b"x").expect("seed");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).expect("chmod");

        write_atomically(&p, b"y").expect("write");

        let mode = fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "renaming a temp over the trust store must not restore a world-readable mode"
        );
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(all(test, unix))]
mod watcher_rearm_tests {
    //! A failed write must never leave the config watcher dead.
    //!
    //! #85/#90: the watcher is unwatched for the duration of a `write_back` so
    //! hops does not react to its own write. If the write fails, the re-arm has
    //! to happen anyway — otherwise the daemon stops noticing hand-edits for the
    //! rest of the process's life. That was measured once as "4 reloads before,
    //! 0 after", followed by the daemon overwriting three hand-edits from stale
    //! memory.
    //!
    //! The first fix added `self.watch()` to the write-error path only. The `?`
    //! on `create_dir_all` above it still returned early with the watcher off,
    //! so the bug survived in a narrower form. The lesson is that "remember to
    //! re-arm before each return" is not a fix — one exit point is.

    use super::*;

    /// Everything between `unwatch` and `watch` lives in `write_config_file`,
    /// so `write_back` itself must contain no early exit after the unwatch.
    ///
    /// This is structural on purpose. Reproducing a failed write needs a
    /// read-only config dir, and a test that chmods a directory it does not own
    /// is worse than one that reads the source. What it pins is the shape that
    /// made the bug possible, which is the part that regressed once already.
    #[test]
    fn write_back_has_one_exit_after_unwatch() {
        const SRC: &str = include_str!("config.rs");
        // Non-test source only: split on the marker WITHOUT a trailing newline —
        // `include_str!` keeps CRLF on a Windows checkout, and a trailing \n
        // there matches a \r and never fires (that bug shipped once already).
        let src = SRC.split("\n#[cfg(test)]").next().unwrap_or(SRC);
        let body = src
            .split("fn write_back(")
            .nth(1)
            .expect("write_back must exist; if renamed, update this guard");
        let body = &body[..body.find("\n    fn ").unwrap_or(body.len())];
        let after = body
            .split("self.unwatch()")
            .nth(1)
            .expect("write_back must still unwatch before writing");
        for (n, line) in after.lines().enumerate() {
            let l = line.split("//").next().unwrap_or("");
            assert!(
                !l.contains('?') && !l.trim_start().starts_with("return "),
                "write_back line {n} after unwatch can exit early without re-arming \
                 the watcher: {line:?}. Put the fallible work in write_config_file \
                 instead — the bracket is what makes the re-arm unconditional \
                 (#85, #90)."
            );
        }
    }

    /// And the bracket itself must still be there.
    #[test]
    fn the_bracket_still_re_arms() {
        const SRC: &str = include_str!("config.rs");
        let src = SRC.split("\n#[cfg(test)]").next().unwrap_or(SRC);
        let body = src.split("fn write_back(").nth(1).expect("write_back");
        let body = &body[..body.find("\n    fn ").unwrap_or(body.len())];
        // Strip comments before searching. The prose in write_back explains the
        // re-arm and therefore CONTAINS `self.watch()` — searching raw source
        // found the comment first and read the order backwards.
        let body: String = body
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let body = body.as_str();
        let u = body.find("self.unwatch()").expect("must unwatch");
        let w = body.find("self.watch()").expect(
            "write_back must re-arm the watcher; without it a single failed write \
             stops the daemon noticing hand-edits for the rest of its life",
        );
        assert!(u < w, "the re-arm must come after the unwatch, not before");
    }
}
