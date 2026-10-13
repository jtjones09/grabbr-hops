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
use hops_ipc::{DEFAULT_PORT, Geometry, Position, RevokedEntry};

use input_event::scancode::{
    self,
    Linux::{KeyLeftAlt, KeyLeftCtrl, KeyLeftMeta, KeyLeftShift},
};

mod merge;

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

/// This build, as a daemon states it to its frontends and a frontend compares
/// it with the daemon's: the same two values `hops --version` prints.
pub fn this_build() -> hops_ipc::Build {
    hops_ipc::Build {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("HOPS_SHORT_COMMIT").to_string(),
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

// The directory keeps the upstream name on purpose, for config compatibility;
// the identity shown to users is com.grabbr.hops (input_event::APP_ID).
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
    /// Fingerprints a build before the trust store removed. Read once, when
    /// the store is first made, so a device removed then is not carried
    /// forward; never written again, since removing a device now forgets it
    /// (#184). The daemon's next save drops the table.
    #[serde(default)]
    revoked_fingerprints: Option<HashMap<String, RevokedEntry>>,
    /// Announce this machine on the local network over mDNS, and look for
    /// others. Default ON — without it there is no way to add a device except
    /// typing an address, which is the hardest rung of the ladder, not the
    /// easiest (#136).
    ///
    /// What advertising discloses: this machine runs hops, its hostname, its
    /// LAN addresses, and its public certificate fingerprint. On a home LAN
    /// that is comparable to what Bonjour already announces about every Mac,
    /// and the listener on this port is findable by a scan regardless. On a
    /// network where "this machine runs a KVM" is itself sensitive, set
    /// `discovery = false` — hops still works, you just type addresses.
    #[serde(default)]
    discovery: Option<bool>,
    /// Listen for peers on `port`. Default ON. `false` makes this a machine
    /// that only dials out (#15): it binds no port, announces nothing, and is
    /// driven only over the links it dials to the machines that control it,
    /// which is how a machine behind a client that drops unsolicited inbound
    /// connections is controlled at all.
    #[serde(default)]
    listen: Option<bool>,
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
    /// What the device is called, apart from where it is dialled (#13).
    #[serde(default)]
    label: Option<String>,
    /// Where the device is drawn on the arrange canvas (#174). Only the
    /// picture: which edge the pointer crosses at is `position`.
    /// Last, as a config may list a device's fields in order.
    #[serde(default)]
    geometry: Option<Geometry>,
}

impl ConfigToml {
    /// The config at `path`, and the text it was parsed from.
    fn read(path: &Path) -> Result<(ConfigToml, String), ConfigError> {
        let text = fs::read_to_string(path)?;
        Ok((toml_edit::de::from_str::<_>(&text)?, text))
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
    /// report whether this binary matches the source it was built from
    ///
    /// Launchers run this before starting anything, so a stale binary is
    /// noticed at launch rather than halfway through a test session.
    BuildCheck {
        /// top of the checkout to compare against (default: $HOPS_REPO when
        /// set and not empty, else the checkout the working directory is in)
        #[arg(long)]
        repo: Option<PathBuf>,
        /// exit 2 when stale and 3 when nothing could be compared (for example
        /// no checkout at the path, a path below the top of one, a checkout
        /// with nothing committed, no git, or a binary built without a commit
        /// baked in; the report says why) — for
        /// dev launchers, where testing an old binary measures the wrong code.
        /// Daily launchers omit it: a promoted build is deliberately behind and
        /// must still start.
        #[arg(long)]
        strict: bool,
    },
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
    /// the (optional) toml config and it's path
    config_toml: Option<ConfigToml>,
    /// `[[clients]]` as this process last read them from the file or wrote
    /// them to it: what a save compares memory against to find what the
    /// daemon changed, which is all it may write (#7).
    synced: Vec<ConfigClient>,
    /// The file's text as this process last read or wrote it: one that
    /// still reads the same holds no edit to take in. `None` after a save
    /// that kept an edit not yet read, so the next read takes it in.
    seen: Option<String>,
    // filesystem watcher, on a thread of its own
    watcher: Watching,
    // channel for filesystem events
    watch_rx: tokio::sync::mpsc::Receiver<Result<notify::Event, notify::Error>>,
    // the watcher's thread is gone, and that was reported
    watch_stopped: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConfigClient {
    pub label: Option<String>,
    pub ips: HashSet<IpAddr>,
    pub hostname: Option<String>,
    pub port: u16,
    pub pos: Position,
    pub active: bool,
    pub enter_hook: Option<String>,
    pub fingerprint: Option<String>,
    pub geometry: Option<Geometry>,
}

impl From<TomlClient> for ConfigClient {
    fn from(toml: TomlClient) -> Self {
        let active = toml.activate_on_startup.unwrap_or(false);
        // as a name given over IPC is (ClientManager::set_label)
        let label = toml
            .label
            .map(|l| hops_ipc::identity::sanitize_label(l.trim()))
            .filter(|l| !l.trim().is_empty());
        let enter_hook = toml.enter_hook;
        let hostname = toml.hostname;
        let ips = HashSet::from_iter(toml.ips.into_iter().flatten());
        let port = toml.port.unwrap_or(DEFAULT_PORT);
        let pos = toml.position.unwrap_or_default();
        // reject a malformed value rather than letting it reach the pin
        let fingerprint = toml
            .fingerprint
            .filter(|fp| hops_ipc::identity::valid_fingerprint(fp));
        let geometry = toml.geometry;
        Self {
            label,
            ips,
            hostname,
            port,
            pos,
            active,
            enter_hook,
            fingerprint,
            geometry,
        }
    }
}

impl From<ConfigClient> for TomlClient {
    fn from(client: ConfigClient) -> Self {
        let label = client.label;
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
        let geometry = client.geometry;
        Self {
            label,
            hostname,
            host_name,
            ips,
            port,
            position,
            activate_on_startup,
            enter_hook,
            fingerprint,
            geometry,
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
/// Same pattern, and the same reason, as `hops_ipc::token::write_private`,
/// including `O_NOFOLLOW`: a daemon running with more privilege than the owner
/// of this directory must not truncate whatever a link here points at (#196).
fn create_private(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| crate::new_file::link_refused(path, e))
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
/// A link is left alone: `metadata` and `set_permissions` both follow one, so
/// tightening through it would change the mode of whatever it points at, which
/// a daemon with more privilege than this directory's owner must not do (#196).
#[cfg(unix)]
fn harden_existing(config_dir: &Path, config_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let tighten = |p: &Path, want: u32| {
        if fs::symlink_metadata(p).is_ok_and(|meta| meta.file_type().is_symlink()) {
            log::warn!(
                "{} is a symbolic link; leaving its permissions alone",
                p.display()
            );
            return;
        }
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

/// Subtract the removals from the allowlist. Pure, so the rule can be tested
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
///
/// Holds the sibling lock [`crate::new_file`] renames a new file into place
/// under where there are no hard links, for the write and the rename. A process
/// creating the default config there checks that nothing is at the path and
/// renames under that lock, so it never replaces what this saved. Where the lock
/// cannot be taken, a filesystem without file locks, no creator can take it
/// either and none renames, so the save goes ahead without it.
pub(crate) fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), io::Error> {
    let _lock = crate::new_file::lock_sibling(path)
        .inspect_err(|e| log::debug!("saving {} without its lock: {e}", path.display()))
        .ok();
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

/// What the `[authorized_fingerprints]` table of `config` lists, keys
/// lowercased, less anything `[revoked_fingerprints]` lists; `None` when it
/// has no such table.
fn listed_in(config: &ConfigToml) -> Option<HashMap<String, String>> {
    let listed = config
        .authorized_fingerprints
        .as_ref()?
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();
    let revoked = config
        .revoked_fingerprints
        .iter()
        .flatten()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();
    Some(subtract_revoked(listed, &revoked).0)
}

/// Make sure a config is at `path`, writing the default when none is, after
/// removing what an earlier process that ended part-way through writing one
/// left beside it.
pub(crate) fn ensure_config_file(path: &Path) -> io::Result<()> {
    crate::new_file::remove_abandoned_temporaries(path);
    if path.exists() {
        return Ok(());
    }
    write_default_config(path)
}

/// Write the default config to `path`, unless a config is already there.
///
/// Every `hops` process that reads the config runs this, and several start
/// together: the daemon, the tray at login, the app opened by hand. The file
/// is created whole and never over one another process has just written.
/// Opening it with `truncate` instead let a process that found no config a
/// moment earlier empty the one another had since saved, devices included.
fn write_default_config(path: &Path) -> io::Result<()> {
    let default_toml = toml_edit::ser::to_string_pretty(&ConfigToml::default())
        .expect("default ConfigToml serialization cannot fail");
    match crate::new_file::create_whole(
        path,
        default_toml.as_bytes(),
        crate::new_file::Access::OwnerReadWrite,
    ) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

/// The subcommand, parsed from argv alone.
///
/// `build-check` is a diagnostic, so it has to answer when the config file is
/// unreadable — which is precisely when someone is trying to find out what is
/// wrong. `Config::new()` loads and validates that file before any subcommand
/// is dispatched, so a single bad line there made the check exit 1 having never
/// run, and every launcher reported "stale, rebuild" for a problem no rebuild
/// could fix.
pub fn command_from_args() -> Option<Command> {
    Args::parse().command
}

impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        Self::with_args(Args::parse())
    }

    /// The config of a daemon a test runs in-process: `hops --config
    /// <config> --cert-path <cert> daemon`, never the test's own arguments.
    /// Unix only, like the one test module that runs a daemon this way.
    #[cfg(all(test, unix))]
    pub(crate) fn in_scratch(config: &Path, cert: &Path) -> Result<Self, ConfigError> {
        use std::ffi::OsStr;
        let args = [
            OsStr::new("hops"),
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--cert-path"),
            cert.as_os_str(),
            OsStr::new("daemon"),
        ];
        Self::with_args(Args::try_parse_from(args).expect("a daemon's arguments"))
    }

    fn with_args(args: Args) -> Result<Self, ConfigError> {
        Self::with_args_watched(args, |on_event| {
            Ok(Box::new(RecommendedWatcher::new(
                on_event,
                notify::Config::default(),
            )?))
        })
    }

    /// [`Self::with_args`], watching with the watcher `watcher` makes from
    /// the handler it is given.
    fn with_args_watched(
        args: Args,
        watcher: impl FnOnce(OnEvent) -> Result<Box<dyn Watcher + Send>, notify::Error>,
    ) -> Result<Self, ConfigError> {
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
        ensure_config_file(&config_path)?;
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
        let (config_toml, seen) = match ConfigToml::read(&config_path) {
            Err(e) => {
                log::error!(
                    "{config_path:?} exists but could not be parsed: {e}\n\
                     Refusing to start. Continuing would discard every authorized \
                     device AND every revocation on the next save. Fix the file, or \
                     move it aside to start fresh."
                );
                return Err(e);
            }
            // The text as read, so a first save is not read back as an edit.
            Ok((c, text)) => (Some(c), Some(text)),
        };

        // --cert-path <file> overrules default location
        let cert_path = args
            .cert_path
            .clone()
            .or(config_toml.as_ref().and_then(|c| c.cert_path.clone()))
            .unwrap_or(default_path()?.join(CERT_FILE_NAME));

        let (tx, watch_rx) = tokio::sync::mpsc::channel(16);
        // Weak, so the channel still closes when the watcher is gone.
        let rearmed = tx.downgrade();
        let watched = config_path.clone();
        let mut watcher = watcher(Box::new(move |res| forward_watch_event(&tx, &watched, res)))?;
        // Armed here the first time, so a directory that cannot be watched
        // fails the start; the thread takes every later order.
        watcher.watch(&config_dir, notify::RecursiveMode::NonRecursive)?;
        let watcher = Watching::keep(watcher, config_dir, move || {
            if let Some(tx) = rearmed.upgrade() {
                let _ = tx.try_send(Ok(read_again()));
            }
        })?;
        let mut config = Config {
            args,
            cert_path,
            config_path,
            config_toml,
            synced: vec![],
            seen,
            watcher,
            watch_rx,
            watch_stopped: false,
        };
        config.synced = config.clients();
        Ok(config)
    }

    /// Order the watcher armed. Returns at once: the watcher's thread does it.
    fn watch(&mut self) -> Result<(), notify::Error> {
        self.watcher.order(Arm::On)
    }

    /// Order the watcher disarmed. Returns at once, like [`Self::watch`].
    fn unwatch(&mut self) -> Result<(), notify::Error> {
        self.watcher.order(Arm::Off)
    }

    pub async fn changed(&mut self) -> Result<(), notify::Error> {
        loop {
            if self.watch_stopped {
                return std::future::pending().await;
            }
            let Some(event) = self.watch_rx.recv().await else {
                // The watcher's thread is gone, and with it every event.
                // Said once: the daemon asks again on every pass of its loop.
                self.watch_stopped = true;
                log::error!(
                    "the config watcher stopped: edits to {:?} are read again \
                     only when hops restarts",
                    self.config_path
                );
                return std::future::pending().await;
            };
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    log::warn!("the config watcher reported an error: {e}");
                    continue;
                }
            };
            if !changes_config(&event, &self.config_path) {
                continue;
            }
            // A read that fails changed nothing in memory: reported, it
            // would have the daemon reload every device for no edit.
            match self.read_if_edited() {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(e) => log::warn!("could not read {:?}: {e}", self.config_path),
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

    /// Fingerprints a build before the trust store removed (#184).
    ///
    /// Keys are lowercased on read for exactly the same reason
    /// [`Self::authorized_fingerprints`] does it: the two tables are compared
    /// against each other, and normalising only one of them is what let an
    /// removed fingerprint be re-authorized in uppercase (issue #67).
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

    /// What the `[authorized_fingerprints]` table lists now, less anything
    /// `[revoked_fingerprints]` lists; `None` when the file has no such table.
    /// Read only to find devices removed from it (`crate::cache_listed`): the
    /// table grants nothing.
    pub fn listed_as_trusted(&self) -> Option<HashMap<String, String>> {
        listed_in(self.config_toml.as_ref()?)
    }

    /// [`Self::listed_as_trusted`], read from the file on disk now rather
    /// than from the config last read. `None` when the file cannot be read,
    /// is empty or does not parse: a file being written says nothing about
    /// which devices it lists.
    pub fn listed_on_disk(&self) -> Option<HashMap<String, String>> {
        let text = fs::read_to_string(&self.config_path).ok()?;
        if text.trim().is_empty() {
            return None;
        }
        let document = text.parse::<DocumentMut>().ok()?;
        listed_in(&toml_edit::de::from_document::<ConfigToml>(document).ok()?)
    }

    /// Drop the `[revoked_fingerprints]` table at the next write: removing a
    /// device forgets it, so no record of the removal is kept anywhere (#184).
    pub fn clear_revoked_fingerprints(&mut self) {
        if let Some(c) = self.config_toml.as_mut() {
            c.revoked_fingerprints = None;
        }
    }

    #[cfg(test)]
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
    /// Whether to advertise on and browse the local network. See
    /// `ConfigToml::discovery` for what advertising discloses.
    pub fn discovery(&self) -> bool {
        self.config_toml
            .as_ref()
            .and_then(|c| c.discovery)
            .unwrap_or(true)
    }

    /// Whether this machine listens for peers. `false`: it only dials out
    /// (#15), and binds no port.
    pub fn listen(&self) -> bool {
        self.config_toml
            .as_ref()
            .and_then(|c| c.listen)
            .unwrap_or(true)
    }

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
        let text = fs::read_to_string(&self.config_path)?;
        self.take_in(text)
    }

    /// [`Self::read_from_disk`], unless the file reads as this process last
    /// read or wrote it. Every save has the file read once more when the
    /// watcher is armed again, and a save seldom reads back exactly as the
    /// config it was made from (an empty table is left out), so without
    /// this each save would be taken in as an edit.
    fn read_if_edited(&mut self) -> Result<bool, io::Error> {
        let text = fs::read_to_string(&self.config_path)?;
        if self.seen.as_deref() == Some(text.as_str()) {
            return Ok(false);
        }
        self.take_in(text)
    }

    /// Take in `text`, read from the file, as the config.
    fn take_in(&mut self, text: String) -> Result<bool, io::Error> {
        log::info!("reading config from {:?}", self.config_path);

        // Saving in place truncates the file, then writes it, and the watcher
        // can report the empty file between the two. Read as a config it has
        // no devices, so every device would be dropped until the next read:
        // an empty file is taken as a save still in progress.
        if text.trim().is_empty() {
            log::info!(
                "{:?} is empty, as while a save is being written; keeping the config as it was",
                self.config_path
            );
            return Ok(false);
        }
        let current_config = match text.parse::<DocumentMut>() {
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
                self.synced = self.clients();
                self.seen = Some(text);
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

    /// Save what the daemon changed, and nothing else (#7).
    ///
    /// Reads the file and applies to it only the changes the daemon made since
    /// it last read or wrote it (see [`merge`]), so an edit made by hand that
    /// the daemon has not read back, a key this build does not know, and the
    /// comments all survive. A file that does not parse is left as it is and
    /// the save fails: overwriting it would throw away the edit that broke it.
    pub fn write_back(&mut self) -> Result<(), io::Error> {
        log::info!("writing config to {:?}", self.config_path);
        // Never serialise `unwrap_or_default()`. If there is no parsed config in
        // memory, writing is the one thing this must not do — that is how a parse
        // failure became a zero-byte trust store. Unreachable since a corrupt
        // config is now fatal at startup, and kept as the second gate anyway.
        let Some(ours) = self.config_toml.clone() else {
            log::error!(
                "refusing to write {:?}: there is no parsed config in memory, and \
                 writing defaults here would erase the trust store",
                self.config_path
            );
            return Ok(());
        };

        // Bracket the write. EVERY exit between unwatch and watch must re-arm,
        // and the way to guarantee that is to have exactly one exit — not to
        // remember a `self.watch()` before each `return`. #85/#90 were filed
        // because a failed write left the watcher dead for the life of the
        // process ("4 reloads before, 0 after"), and the fix at the time added
        // the re-arm to the write-error path only. The `?` on create_dir_all
        // above it still returned early with the watcher off.
        //
        // Both are orders to the watcher's thread and return at once: done
        // here, on macOS they waited on the system's file-event service,
        // which under load held the daemon loop for seconds per save. So the
        // unwatch no longer lands before the write, and the daemon can read
        // its own save back: it reads the same config, or one that also holds
        // an edit not yet read, which a reload then takes in. Armed again,
        // the watcher reports only what happens from then on, so the thread
        // has the file read once more after each re-arm: an edit saved while
        // it was disarmed, which on macOS is seconds under load, is read too.
        let _ = self.unwatch();
        let result = self.write_config_file(&ours);
        let _ = self.watch();
        result
    }

    /// The actual read, merge and write. Called only between `unwatch` and
    /// `watch`, so it is free to use `?` — its caller re-arms on every path.
    ///
    /// Reading inside the bracket narrows what can still be lost to an edit
    /// saved between this read and the rename below.
    fn write_config_file(&mut self, ours: &ConfigToml) -> Result<(), io::Error> {
        if let Some(p) = self.config_path().parent() {
            fs::create_dir_all(p)?;
        }
        // Whether the file holds an edit not yet read, which the merge
        // keeps in what it writes.
        let mut unread = false;
        let new_config = match fs::read_to_string(self.config_path()) {
            Ok(disk) => {
                unread = self.seen.as_deref() != Some(disk.as_str());
                merge::merge(&disk, &self.synced, ours).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} was left as it is: {e}", self.config_path.display()),
                    )
                })?
            }
            // nothing on disk to keep
            Err(e) if e.kind() == io::ErrorKind::NotFound => merge::render(ours)
                .map(|doc| doc.to_string())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) => return Err(e),
        };
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
        write_atomically(self.config_path(), new_config.as_bytes())?;
        self.synced = self.clients();
        // What this wrote is no edit to read, unless it kept one: then the
        // next read takes the file in, and the edit with it.
        self.seen = (!unread).then_some(new_config);
        Ok(())
    }
}

/// What a watcher is handed to pass each event on to the daemon loop.
type OnEvent = Box<dyn FnMut(notify::Result<notify::Event>) + Send>;

/// What [`Config::watch`] and [`Config::unwatch`] order the watcher to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    On,
    Off,
}

/// The config directory's watcher, kept on a thread of its own so that no
/// order to it waits: arming or disarming it asks the operating system,
/// which can take seconds, and the daemon loop that saves the config also
/// carries the input.
#[derive(Debug)]
struct Watching {
    orders: std::sync::mpsc::Sender<Arm>,
}

impl Watching {
    /// Keep `watcher`, armed on `dir`, on a new thread that carries out
    /// each order in turn, calling `rearmed` after each order to arm it:
    /// it then reports only what happens from then on, so what happened
    /// while it was disarmed is for `rearmed` to catch. The thread ends,
    /// dropping the watcher there too, when this is dropped.
    fn keep(
        mut watcher: Box<dyn Watcher + Send>,
        dir: PathBuf,
        rearmed: impl Fn() + Send + 'static,
    ) -> io::Result<Watching> {
        let (orders, taken) = std::sync::mpsc::channel::<Arm>();
        std::thread::Builder::new()
            .name("hops config watcher".to_string())
            .spawn(move || {
                for arm in taken {
                    match arm {
                        Arm::On => {
                            if let Err(e) = watcher.watch(&dir, notify::RecursiveMode::NonRecursive)
                            {
                                log::warn!("the config watcher could not watch {dir:?}: {e}");
                            }
                            rearmed();
                        }
                        Arm::Off => {
                            let _ = watcher.unwatch(&dir);
                        }
                    }
                }
            })?;
        Ok(Watching { orders })
    }

    /// Hand `arm` to the watcher's thread, never waiting for it.
    fn order(&self, arm: Arm) -> Result<(), notify::Error> {
        self.orders
            .send(arm)
            .map_err(|_| notify::Error::generic("the config watcher's thread is gone"))
    }
}

/// Whether `event` can mean the config file at `config` was replaced, written
/// or removed.
///
/// A save that writes a new file and renames it over the config, as editors
/// and tools do, is reported as a rename, not as a create or a write. A
/// rescan notice names no file and can mean any of them: the system sends
/// one when it dropped events, and the watcher's thread one when it was
/// armed again ([`read_again`]).
fn changes_config(event: &notify::Event, config: &Path) -> bool {
    event.need_rescan()
        || event.paths.iter().any(|p| p == config)
            && matches!(
                event.kind,
                EventKind::Create(_)
                    | EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Name(_))
                    | EventKind::Remove(_)
            )
}

/// The notice the watcher's thread passes on each time it is armed again:
/// read the file once more, for any edit made while it was disarmed.
fn read_again() -> notify::Event {
    notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan)
}

/// Hand a watcher event to the daemon loop. Runs on the watcher's thread.
///
/// It must never wait for the loop: `unwatch` is ordered around every
/// config write, and on Linux `unwatch` waits for this thread, so a thread
/// blocked on a full channel once stopped the daemon for good (#227), and
/// would now leave the watcher dead. Only events
/// that can change the config take a slot, and when the channel is full the
/// event is dropped: every event already queued re-reads the file when it is
/// handled, so the latest content is still picked up. Errors are passed on
/// the same way.
fn forward_watch_event(
    tx: &tokio::sync::mpsc::Sender<Result<notify::Event, notify::Error>>,
    config: &Path,
    res: Result<notify::Event, notify::Error>,
) {
    if let Ok(event) = &res {
        if !changes_config(event, config) {
            return;
        }
    }
    let _ = tx.try_send(res);
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

    // LEDGER T3 | class B | 1 error + 4 file on disk: config::write_atomically
    #[test]
    #[cfg(unix)]
    fn a_save_refuses_a_link_where_its_temporary_belongs() {
        let d = tmpdir("save-link");
        let p = d.join("config.toml");
        fs::write(&p, b"port = 4242\n").expect("seed");
        let target = d.join("someone-elses-file");
        fs::write(&target, b"keep me\n").expect("seed target");
        std::os::unix::fs::symlink(&target, d.join("config.toml.tmp")).expect("link");

        let refused = write_atomically(&p, b"port = 4243\n").expect_err("a link must be refused");
        assert!(
            refused.to_string().contains("symbolic link"),
            "the refusal must say why: {refused}"
        );
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            "keep me\n",
            "the link's target must be untouched"
        );
        assert_eq!(
            fs::read_to_string(&p).expect("read"),
            "port = 4242\n",
            "the config itself must be untouched"
        );
        let _ = fs::remove_dir_all(&d);
    }

    // LEDGER T4 | class B | 4 file on disk: config::harden_existing
    #[test]
    #[cfg(unix)]
    fn hardening_leaves_a_link_and_its_target_alone() {
        let d = tmpdir("harden-link");
        let target = d.join("someone-elses-file");
        fs::write(&target, b"keep me\n").expect("seed");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("chmod");
        let p = d.join("config.toml");
        std::os::unix::fs::symlink(&target, &p).expect("link");

        harden_existing(&d, &p);

        assert_eq!(
            mode_of(&target),
            0o644,
            "a link's target must keep its own permissions"
        );
        let _ = fs::remove_dir_all(&d);
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
mod the_default_config_never_replaces_one {
    //! Every `hops` process writes the default config when it finds none, and
    //! the daemon, the tray and the app often start together. One of them can
    //! find no config, and by the time it writes, another has written one.

    use super::*;

    // LEDGER T18 | class B | 4 file on disk
    #[test]
    fn a_config_written_after_the_check_is_kept() {
        let d = std::env::temp_dir().join(format!("hops-default-config-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        // `Config::new` creates the directory before it writes a default.
        fs::create_dir_all(&d).expect("the config directory");
        let p = d.join("config.toml");

        let first = write_default_config(&p);
        let default_parses = ConfigToml::read(&p).is_ok();
        // What the daemon saved after this process found no config.
        let saved = "port = 4343\n\n[authorized_fingerprints]\n\"aa:bb\" = \"laptop\"\n";
        fs::write(&p, saved).expect("the daemon's save");
        let second = write_default_config(&p);
        let on_disk = fs::read_to_string(&p).unwrap_or_default();
        let _ = fs::remove_dir_all(&d);

        assert!(
            first.is_ok() && default_parses,
            "no default config was written where there was none: {first:?}"
        );
        assert!(
            second.is_ok(),
            "finding a config already there is not an error: {second:?}"
        );
        assert_eq!(
            on_disk, saved,
            "the default config replaced one written since the check, and the \
             authorized devices in it were lost"
        );
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
                        label: "removed".into(),
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
    fn case_does_not_launder_a_removal() {
        // The exact shape of issue #67: removed in lowercase, re-added upper.
        let (a, refused) =
            subtract_revoked(allow(&[(&A.to_uppercase(), "attacker")]), &revoked(&[A]));
        assert!(
            a.is_empty(),
            "uppercasing a revoked fingerprint must not resurrect it"
        );
        assert_eq!(refused, vec![A.to_string()]);
    }

    #[test]
    fn a_removal_written_in_uppercase_still_bites() {
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
        let err = ConfigToml::read(&p).expect_err("a type error must not parse");
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
            .find("let (config_toml, seen) = match ConfigToml::read(&config_path)")
            .expect("the parse site must exist; if it moved, update this guard");
        let arm = &src[start..start + 900];
        let err_arm = arm.split("Err(e) =>").nth(1).expect("an Err arm");
        let err_arm = &err_arm[..err_arm.find("Ok((c").unwrap_or(err_arm.len())];
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

// Not unix-gated: these read source text, so they are worth running on the
// Windows runner too — that is where the last source-scanning guard broke.
#[cfg(test)]
mod watcher_rearm_tests {
    //! A failed write must never leave the config watcher dead.
    //!
    //! #85/#90: the watcher is unwatched around a `write_back`, once so hops
    //! did not react to its own write. If the write fails, the re-arm has
    //! to happen anyway — otherwise the daemon stops noticing hand-edits for the
    //! rest of the process's life. That was measured once as "4 reloads before,
    //! 0 after", followed by the daemon overwriting three hand-edits from stale
    //! memory.
    //!
    //! The first fix added `self.watch()` to the write-error path only. The `?`
    //! on `create_dir_all` above it still returned early with the watcher off,
    //! so the bug survived in a narrower form. The lesson is that "remember to
    //! re-arm before each return" is not a fix — one exit point is.

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

#[cfg(test)]
mod the_watcher_never_blocks {
    //! The watcher thread hands events to the daemon loop, and `unwatch`, which
    //! is ordered around every config write, waits for that thread. So the
    //! thread must never wait for the loop: a burst of other files written in
    //! the config directory once filled the channel, blocked the thread, and
    //! with it the daemon, for good (#227).
    use super::*;
    use notify::event::{AccessKind, CreateKind, DataChange, MetadataKind};
    use std::sync::mpsc;
    use std::time::Duration;

    fn event(kind: EventKind, path: &Path) -> notify::Result<notify::Event> {
        Ok(notify::Event::new(kind).add_path(path.to_path_buf()))
    }

    // LEDGER T1 | class B | 1 return value: forward_watch_event on a bounded channel
    #[test]
    fn a_full_channel_does_not_block_the_watcher_thread() {
        let dir = PathBuf::from("/nonexistent-hops-config");
        let config = dir.join("config.toml");
        let other = dir.join("trust.sealed.tmp");
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            // many times the channel's size, as a trust save and a config
            // write produce in one request, and nobody draining
            for _ in 0..64 {
                forward_watch_event(
                    &tx,
                    &config,
                    event(EventKind::Create(CreateKind::File), &other),
                );
                forward_watch_event(
                    &tx,
                    &config,
                    event(
                        EventKind::Modify(ModifyKind::Data(DataChange::Any)),
                        &config,
                    ),
                );
            }
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the watcher thread blocked on a full channel; unwatch would wait for it forever"
        );

        let mut kept = Vec::new();
        while let Ok(e) = rx.try_recv() {
            kept.push(e.expect("event"));
        }
        assert!(
            !kept.is_empty() && kept.iter().all(|e| e.paths == [dir.join("config.toml")]),
            "the channel must still hold a change to the config file, and nothing \
             else: {kept:?}"
        );
    }

    // LEDGER W6 | class B | 1 return value: forward_watch_event with a rescan notice
    /// When the system drops events it says so with a rescan notice, which
    /// names no file: whatever it dropped may have been an edit.
    #[test]
    fn a_rescan_notice_takes_a_slot() {
        let config = PathBuf::from("/nonexistent-hops-config/config.toml");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        forward_watch_event(
            &tx,
            &config,
            Ok(notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan)),
        );
        assert!(
            rx.try_recv().is_ok(),
            "a notice that events were dropped was filtered out, so an edit among them \
             is never read"
        );
    }

    // LEDGER T2 | class B | 1 return value: forward_watch_event filtering
    #[test]
    fn only_a_change_to_the_config_file_takes_a_slot() {
        let dir = PathBuf::from("/nonexistent-hops-config");
        let config = dir.join("config.toml");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for e in [
            event(EventKind::Create(CreateKind::File), &dir.join("other")),
            event(EventKind::Access(AccessKind::Any), &config),
            event(
                EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
                &config,
            ),
        ] {
            forward_watch_event(&tx, &config, e);
        }
        assert!(
            rx.try_recv().is_err(),
            "an event that cannot change the config took a slot"
        );
        forward_watch_event(
            &tx,
            &config,
            event(EventKind::Create(CreateKind::File), &config),
        );
        assert!(rx.try_recv().is_ok(), "a new config file was not passed on");
    }
}

#[cfg(test)]
mod a_save_never_waits_for_the_watcher {
    //! Arming or disarming the watcher asks the operating system, and on
    //! macOS under load each call took seconds. Every save disarmed and
    //! re-armed it on the daemon loop, which also carries the input and the
    //! pairing comparison, so one save could hold both past the comparison's
    //! ten second step.
    use super::*;
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::{Duration, Instant};

    /// Far longer than a save takes, however loaded the run.
    const DEADLINE: Duration = Duration::from_secs(30);

    #[derive(Default)]
    struct Gate {
        open: bool,
        calls: Vec<Arm>,
    }

    /// The calls a watcher took, each held until the gate is open.
    #[derive(Clone, Default)]
    struct Busy(Arc<(Mutex<Gate>, Condvar)>);

    impl Busy {
        fn call(&self, arm: Arm) {
            let (gate, changed) = &*self.0;
            let mut g = gate.lock().expect("gate");
            g.calls.push(arm);
            changed.notify_all();
            while !g.open {
                g = changed.wait(g).expect("gate");
            }
        }

        /// Take `arm` without waiting at the gate.
        fn record(&self, arm: Arm) {
            let (gate, changed) = &*self.0;
            gate.lock().expect("gate").calls.push(arm);
            changed.notify_all();
        }

        fn set_open(&self, open: bool) {
            let (gate, changed) = &*self.0;
            gate.lock().expect("gate").open = open;
            changed.notify_all();
        }

        /// The calls taken once there are `n`, or at the deadline.
        fn calls(&self, n: usize) -> Vec<Arm> {
            let (gate, changed) = &*self.0;
            let end = Instant::now() + DEADLINE;
            let mut g = gate.lock().expect("gate");
            while g.calls.len() < n && Instant::now() < end {
                g = changed
                    .wait_timeout(g, end.saturating_duration_since(Instant::now()))
                    .expect("gate")
                    .0;
            }
            g.calls.clone()
        }
    }

    struct BusyWatcher(Busy);

    impl Watcher for BusyWatcher {
        fn new<F: notify::EventHandler>(_: F, _: notify::Config) -> notify::Result<Self> {
            Err(notify::Error::generic("made by the test"))
        }
        fn watch(&mut self, _: &Path, _: notify::RecursiveMode) -> notify::Result<()> {
            self.0.call(Arm::On);
            Ok(())
        }
        fn unwatch(&mut self, _: &Path) -> notify::Result<()> {
            self.0.call(Arm::Off);
            Ok(())
        }
        fn kind() -> notify::WatcherKind {
            notify::WatcherKind::NullWatcher
        }
    }

    /// A watcher that is slow only to arm, as on macOS, and reports nothing,
    /// as a watcher armed after an edit never reports it. It keeps the
    /// handler it is given, so it is never taken for a watcher that is gone.
    struct ArmingWatcher {
        busy: Busy,
        _events: OnEvent,
    }

    impl Watcher for ArmingWatcher {
        fn new<F: notify::EventHandler>(_: F, _: notify::Config) -> notify::Result<Self> {
            Err(notify::Error::generic("made by the test"))
        }
        fn watch(&mut self, _: &Path, _: notify::RecursiveMode) -> notify::Result<()> {
            self.busy.call(Arm::On);
            Ok(())
        }
        fn unwatch(&mut self, _: &Path) -> notify::Result<()> {
            self.busy.record(Arm::Off);
            Ok(())
        }
        fn kind() -> notify::WatcherKind {
            notify::WatcherKind::NullWatcher
        }
    }

    /// A config in a scratch directory, watched by a [`BusyWatcher`] whose
    /// gate is open for the first arming and closed after it.
    fn watched(tag: &str) -> (PathBuf, PathBuf, Config, Busy) {
        watched_by(tag, false)
    }

    /// [`watched`], by an [`ArmingWatcher`] when `arming` is true.
    fn watched_by(tag: &str, arming: bool) -> (PathBuf, PathBuf, Config, Busy) {
        let dir = std::env::temp_dir().join(format!("hops-watch-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("config.toml");
        fs::write(&path, "port = 4343\n").expect("a config");
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--cert-path".as_ref(),
            dir.join("cert.pem").as_os_str(),
        ]);
        let busy = Busy::default();
        busy.set_open(true);
        let watcher = busy.clone();
        let config = Config::with_args_watched(args, move |on_event| {
            Ok(if arming {
                Box::new(ArmingWatcher {
                    busy: watcher,
                    _events: on_event,
                })
            } else {
                Box::new(BusyWatcher(watcher))
            })
        })
        .expect("the config loads");
        busy.set_open(false);
        (dir, path, config, busy)
    }

    /// Save on a thread of its own; what the save returned, or `None` if it
    /// had not returned by the deadline.
    fn saved(mut config: Config) -> Option<Result<(), io::Error>> {
        let (done, returned) = mpsc::channel();
        std::thread::spawn(move || {
            let r = config.write_back();
            let _ = done.send(r);
            // Dropped here, with the watcher's thread left to end.
        });
        returned.recv_timeout(DEADLINE).ok()
    }

    // LEDGER W1 | class B | 2 thread + struct state: Config::write_back against a watcher that does not answer
    #[test]
    fn a_save_returns_while_the_watcher_is_still_busy() {
        let (dir, path, config, busy) = watched("busy");
        let returned = saved(config);
        busy.set_open(true);
        let calls = busy.calls(3);
        let written = fs::read_to_string(&path).unwrap_or_default();
        let _ = fs::remove_dir_all(&dir);
        assert!(
            returned.is_some(),
            "a config save waited for the file watcher, which can take seconds: \
             the daemon loop that saves also carries the input"
        );
        assert!(
            matches!(returned, Some(Ok(()))) && written.contains("4343"),
            "the save failed: {returned:?}, file: {written:?}"
        );
        assert_eq!(
            calls,
            [Arm::On, Arm::Off, Arm::On],
            "the watcher was not disarmed and re-armed, in that order, once the save \
             was done"
        );
    }

    // LEDGER W2 | class B | 2 thread + struct state: the watcher's calls after a save that failed
    #[test]
    fn a_save_that_fails_leaves_the_watcher_armed() {
        let (dir, path, config, busy) = watched("failed");
        busy.set_open(true);
        // Not a config: the save leaves it as it is and fails (#85, #90).
        fs::write(&path, "port = [\n").expect("a broken config");
        let returned = saved(config);
        let calls = busy.calls(3);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(returned, Some(Err(_))),
            "precondition: the save of a broken config fails: {returned:?}"
        );
        assert_eq!(
            calls.last(),
            Some(&Arm::On),
            "a save that failed left the config watcher disarmed, so edits are never \
             read again: {calls:?}"
        );
    }

    // LEDGER W5 | class B | 1 return value + 2 struct state: Config::changed after a save, with an edit made while the watcher was disarmed
    /// A save disarms the watcher and arms it again. Armed again, a watcher
    /// reports only what happens from then on: on macOS arming takes a
    /// second or more, and under load many, so an edit saved by hand in
    /// that time was never reported, and never read until hops restarted.
    #[test]
    fn an_edit_made_while_the_watcher_is_rearmed_is_read() {
        let (dir, path, mut config, busy) = watched_by("rearm", true);
        config.write_back().expect("the save");
        // Held arming again: the edit lands before the watcher reports
        // anything, and so is never reported.
        let calls = busy.calls(3);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        // The daemon reads whatever is already passed on, as its loop does
        // at any moment: a read before the edit does not read the edit.
        let early = rt.block_on(async { futures::FutureExt::now_or_never(config.changed()) });
        let saving = dir.join("config.toml.saving");
        fs::write(&saving, "port = 4444\n").expect("the edit");
        fs::rename(&saving, &path).expect("renamed over the config");
        busy.set_open(true);
        let read = rt.block_on(async {
            tokio::time::timeout(DEADLINE, async {
                while config.port() != 4444 {
                    config.changed().await?;
                }
                Ok::<(), notify::Error>(())
            })
            .await
        });
        let port = config.port();
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            calls,
            [Arm::On, Arm::Off, Arm::On],
            "precondition: the edit was made while the watcher was armed again after the save"
        );
        assert!(
            early.is_none(),
            "precondition: nothing changed before the edit: {early:?}"
        );
        assert!(
            matches!(read, Ok(Ok(()))) && port == 4444,
            "an edit saved while hops' own save had the config watcher disarmed was \
             never read: {read:?}, port {port}"
        );
    }

    // LEDGER W8 | class B | 1 return value: Config::changed after a save with no edit, once the watcher is armed again
    /// Armed again after a save, the watcher has the file read once more.
    /// What hops wrote is not an edit: taken in as one, every save would
    /// be followed by a reload of every device and a check for removals.
    #[test]
    fn a_save_is_not_read_back_as_an_edit() {
        let (dir, _path, mut config, busy) = watched_by("own", true);
        busy.set_open(true);
        // As the daemon saves: an empty list in memory, which the file
        // leaves out, so the file does not read back as the same config.
        config.set_clients(vec![]);
        config.write_back().expect("the save");
        // Taken only after the re-arm and the read it asks for.
        let _ = config.unwatch();
        let calls = busy.calls(4);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let read = rt.block_on(async { futures::FutureExt::now_or_never(config.changed()) });
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            calls,
            [Arm::On, Arm::Off, Arm::On, Arm::Off],
            "precondition: the watcher was armed again after the save"
        );
        assert!(
            read.is_none(),
            "hops' own save was read back as an edit to its config: {read:?}"
        );
    }

    /// Wait until `config` holds what `done` says it should, reading every
    /// notice passed on; the deadline, or what a read returned, otherwise.
    fn read_until(
        config: &mut Config,
        done: impl Fn(&Config) -> bool,
    ) -> Result<Result<(), notify::Error>, tokio::time::error::Elapsed> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            tokio::time::timeout(DEADLINE, async {
                while !done(config) {
                    config.changed().await?;
                }
                Ok::<(), notify::Error>(())
            })
            .await
        })
    }

    /// Replace the config by rename, as an editor saves it.
    fn edit(dir: &Path, path: &Path, text: &str) {
        let saving = dir.join("config.toml.saving");
        fs::write(&saving, text).expect("the edit");
        fs::rename(&saving, path).expect("renamed over the config");
    }

    // LEDGER W9 | class B | 1 return value + 2 struct state: Config::changed after a save that merged onto a hand edit not yet read
    /// A save merges the daemon's changes onto the file as it is on disk,
    /// so an edit not yet read is kept in what it writes. What it wrote is
    /// then no edit to read, but the edit it kept still is: a device
    /// removed by hand just before hops saved stayed in memory, with the
    /// file saying it was gone, until hops restarted.
    #[test]
    fn a_hand_edit_kept_by_a_save_is_still_read() {
        let (dir, path, mut config, busy) = watched_by("folded", true);
        busy.set_open(true);
        let two = "port = 4343\n\
                   [[clients]]\nhostname = \"desk-mac\"\nposition = \"left\"\n\
                   [[clients]]\nhostname = \"garage-pc\"\nposition = \"top\"\n";
        edit(&dir, &path, two);
        config.read_from_disk().expect("the two devices");
        let before = config.clients().len();
        edit(
            &dir,
            &path,
            "port = 4343\n[[clients]]\nhostname = \"desk-mac\"\nposition = \"left\"\n",
        );
        // Saved before the edit is read, as when a peer's fingerprint is
        // learned or a frontend asks for a change.
        config.write_back().expect("the save");
        let read = read_until(&mut config, |c| c.clients().len() == 1);
        let on_disk = fs::read_to_string(&path).unwrap_or_default();
        let after = config.clients().len();
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(before, 2, "precondition: both devices were read");
        assert!(
            !on_disk.contains("garage-pc"),
            "precondition: the save kept the removal on disk: {on_disk:?}"
        );
        assert!(
            matches!(read, Ok(Ok(()))) && after == 1,
            "a device removed by hand just before hops saved stays in memory: \
             {read:?}, {after} devices"
        );
    }

    // LEDGER W10 | class B | 1 return value + 1 struct state: Config::changed after two saves with an edit between them, before either re-arm
    /// Saves come in bursts, and each one's re-arm can take seconds. An
    /// edit made while the first save's re-arm was still pending, then
    /// kept by the second save, was never read.
    #[test]
    fn an_edit_between_two_saves_is_read() {
        let (dir, path, mut config, busy) = watched_by("burst", true);
        config.write_back().expect("the first save");
        // The first save's re-arm is held, so nothing is read yet.
        let calls = busy.calls(3);
        edit(&dir, &path, "port = 4444\n");
        config.write_back().expect("the second save");
        busy.set_open(true);
        let read = read_until(&mut config, |c| c.port() == 4444);
        let on_disk = fs::read_to_string(&path).unwrap_or_default();
        let port = config.port();
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            calls,
            [Arm::On, Arm::Off, Arm::On],
            "precondition: the edit was made while the first save's re-arm was pending"
        );
        assert!(
            on_disk.contains("4444"),
            "precondition: the second save kept the edit on disk: {on_disk:?}"
        );
        assert!(
            matches!(read, Ok(Ok(()))) && port == 4444,
            "an edit made between two of hops' own saves was never read: \
             {read:?}, port {port}"
        );
    }

    // LEDGER W11 | class B | 1 return value: Config::changed on a rescan notice when the config cannot be read
    /// A read that fails is no change to report: reported, the daemon
    /// reloads every device from a config that did not change.
    #[test]
    fn a_config_that_cannot_be_read_is_not_reported_as_changed() {
        let (dir, path, mut config, busy) = watched_by("unreadable", true);
        busy.set_open(true);
        fs::remove_file(&path).expect("the config moved away");
        // Armed again: the thread has the file read once more. Taken only
        // once that read has been asked for.
        let _ = config.watch();
        let _ = config.unwatch();
        let calls = busy.calls(3);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let read = rt.block_on(async { futures::FutureExt::now_or_never(config.changed()) });
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            calls,
            [Arm::On, Arm::On, Arm::Off],
            "precondition: the watcher was armed again with no config to read"
        );
        assert!(
            read.is_none(),
            "a config that could not be read was reported as changed: {read:?}"
        );
    }

    /// A watcher that cannot watch anything.
    struct RefusingWatcher;

    impl Watcher for RefusingWatcher {
        fn new<F: notify::EventHandler>(_: F, _: notify::Config) -> notify::Result<Self> {
            Ok(RefusingWatcher)
        }
        fn watch(&mut self, _: &Path, _: notify::RecursiveMode) -> notify::Result<()> {
            Err(notify::Error::generic("this directory cannot be watched"))
        }
        fn unwatch(&mut self, _: &Path) -> notify::Result<()> {
            Ok(())
        }
        fn kind() -> notify::WatcherKind {
            notify::WatcherKind::NullWatcher
        }
    }

    // LEDGER W3 | class B | 1 return value: Config::with_args_watched with a watcher that refuses the config directory
    /// The first arming stays on the caller: a config directory that cannot
    /// be watched fails the start, rather than a daemon coming up that
    /// never reads an edit.
    #[test]
    fn a_directory_that_cannot_be_watched_fails_the_start() {
        let dir = std::env::temp_dir().join(format!("hops-watch-refused-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("config.toml");
        fs::write(&path, "port = 4343\n").expect("a config");
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--cert-path".as_ref(),
            dir.join("cert.pem").as_os_str(),
        ]);
        let started = Config::with_args_watched(args, |_| Ok(Box::new(RefusingWatcher)));
        let _ = fs::remove_dir_all(&dir);
        assert!(
            started.is_err(),
            "a config directory that cannot be watched still started the daemon, which \
             would never read an edit"
        );
    }

    // LEDGER W4 | class B | 1 log record count: Config::changed asked again after the watcher's thread is gone
    /// Once the watcher's thread is gone, [`Config::changed`] says so once
    /// and waits for good. The daemon asks it again on every pass of its
    /// loop, so saying it on every ask fills the log for the rest of the run.
    #[test]
    fn a_stopped_watcher_is_reported_once() {
        // This watcher drops the handler it is given: no event ever comes.
        let (dir, _path, mut config, busy) = watched("stopped");
        busy.set_open(true);
        let logs = crate::test_harness::logs::capture();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        for _ in 0..3 {
            let waited = rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(20), config.changed()).await
            });
            assert!(
                waited.is_err(),
                "changed() returned with no watcher: {waited:?}"
            );
        }
        let said = logs
            .lines()
            .iter()
            .filter(|l| l.text.contains("the config watcher stopped"))
            .count();
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            said, 1,
            "the stopped config watcher was reported {said} times over three asks, once \
             per pass of the daemon loop"
        );
    }
}

#[cfg(test)]
mod a_file_being_written_is_not_read_as_empty {
    //! Saving a file in place truncates it, then writes it. On Linux the
    //! watcher reports both, and the empty file between them parsed as a
    //! valid config with no devices: the daemon dropped every device, and
    //! a broken final version then left them dropped.
    use super::*;

    // LEDGER T30 | class B | 6 struct state: Config::read_from_disk on a truncated file
    #[test]
    fn a_truncated_config_keeps_the_devices_it_had() {
        let dir = std::env::temp_dir().join(format!("hops-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "port = 4343\n[[clients]]\nhostname = \"desk-mac\"\nposition = \"left\"\n",
        )
        .expect("a config");
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--cert-path".as_ref(),
            dir.join("cert.pem").as_os_str(),
        ]);
        let mut config = Config::with_args(args).expect("the config loads");
        assert_eq!(config.clients().len(), 1, "the device the file names");

        fs::write(&path, "").expect("the truncation a save in place starts with");
        let changed = config.read_from_disk().expect("the file reads");
        let kept = config.clients().len();
        let _ = fs::remove_dir_all(&dir);
        assert!(
            !changed && kept == 1,
            "an empty config file, which a save in place passes through, was \
             read as a config with no devices (changed: {changed}, devices: {kept})"
        );
    }
}

#[cfg(all(test, unix))]
mod a_save_by_rename_is_read {
    //! Editors and tools save by writing a new file beside the config and
    //! renaming it over the old one. The watcher reports that as a rename,
    //! which on Linux is neither a create nor a write, and a daemon that
    //! waited for one of those never read the edit.
    use super::*;
    use std::time::Duration;

    // LEDGER T31 | class B | 1 return value + 6 struct state: Config::changed over a real watcher
    #[test]
    fn a_config_renamed_into_place_is_read() {
        let dir = std::env::temp_dir().join(format!("hops-rename-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        // As the watcher reports it: on macOS the temporary directory is
        // reached through a link, and events name the path it links to.
        let dir = dir
            .canonicalize()
            .expect("the scratch directory's real path");
        let path = dir.join("config.toml");
        fs::write(&path, "port = 4343\n").expect("a config");
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--cert-path".as_ref(),
            dir.join("cert.pem").as_os_str(),
        ]);
        let mut config = Config::with_args(args).expect("the config loads");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let saved = dir.join("config.toml.saving");
        fs::write(&saved, "port = 4444\n").expect("the new version");
        fs::rename(&saved, &path).expect("renamed over the config");
        let read = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(20), config.changed()).await
        });
        let port = config.port();
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(read, Ok(Ok(()))) && port == 4444,
            "a config saved by renaming a new file over it was not read: {read:?}, \
             port {port}"
        );
    }
}

#[cfg(all(test, unix))]
mod an_edit_right_after_a_save_is_read {
    //! The same over the system's own watcher: an edit saved while hops'
    //! save is still arming the watcher again.
    use super::*;
    use std::time::Duration;

    // LEDGER W7 | class B | 1 return value + 1 struct state: Config::changed over a real watcher, an edit made as a save returns
    #[test]
    fn an_edit_saved_as_a_save_returns_is_read() {
        let dir = std::env::temp_dir().join(format!("hops-after-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        // As the watcher reports it (see a_config_renamed_into_place_is_read).
        let dir = dir
            .canonicalize()
            .expect("the scratch directory's real path");
        let path = dir.join("config.toml");
        fs::write(&path, "port = 4343\n").expect("a config");
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--cert-path".as_ref(),
            dir.join("cert.pem").as_os_str(),
        ]);
        let mut config = Config::with_args(args).expect("the config loads");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        config.write_back().expect("the save");
        let saving = dir.join("config.toml.saving");
        fs::write(&saving, "port = 4444\n").expect("the edit");
        fs::rename(&saving, &path).expect("renamed over the config");
        // Arming asks the system, which takes each request in turn: in a
        // full test run, with every other test's watcher, it has taken over
        // thirty seconds.
        let read = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(120), async {
                while config.port() != 4444 {
                    config.changed().await?;
                }
                Ok::<(), notify::Error>(())
            })
            .await
        });
        let port = config.port();
        drop(config);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(read, Ok(Ok(()))) && port == 4444,
            "an edit saved just after hops' own save was never read: {read:?}, port {port}"
        );
    }
}

#[cfg(test)]
mod saves_keep_what_they_did_not_set {
    //! A save changes in the file only what the daemon changed (#7).
    //!
    //! Each test loads a real `Config` from a scratch file, changes the file
    //! the way a hand edit does without the daemon reading it back (on
    //! Windows the watcher never reports one, #5), changes memory the way
    //! `save_config` does, saves, and reads what landed on disk.
    use super::*;

    const DESK: &str = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

    struct Scratch {
        dir: PathBuf,
        path: PathBuf,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn scratch(tag: &str, text: &str) -> (Scratch, Config) {
        let dir = std::env::temp_dir().join(format!("hops-merge-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("config.toml");
        fs::write(&path, text).expect("a config");
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--cert-path".as_ref(),
            dir.join("cert.pem").as_os_str(),
        ]);
        let config = Config::with_args(args).expect("the config loads");
        (Scratch { dir, path }, config)
    }

    /// The config in `s` as the next start loads it.
    fn restarted(s: &Scratch) -> Config {
        let args = Args::parse_from([
            "hops".as_ref(),
            "--config".as_ref(),
            s.path.as_os_str(),
            "--cert-path".as_ref(),
            s.dir.join("cert.pem").as_os_str(),
        ]);
        Config::with_args(args).expect("the saved config loads")
    }

    fn on_disk(s: &Scratch) -> DocumentMut {
        fs::read_to_string(&s.path)
            .expect("the config")
            .parse()
            .expect("the saved config parses")
    }

    fn entry(doc: &DocumentMut, i: usize) -> &toml_edit::Table {
        doc["clients"]
            .as_array_of_tables()
            .and_then(|a| a.get(i))
            .unwrap_or_else(|| panic!("no entry {i} in:\n{doc}"))
    }

    /// The value of `key`, without the whitespace and comment around it.
    fn text(t: &toml_edit::Table, key: &str) -> String {
        t.get(key)
            .and_then(|i| i.as_value())
            .map(|v| {
                let mut v = v.clone();
                v.decor_mut().clear();
                v.to_string()
            })
            .unwrap_or_default()
    }

    const TWO_DEVICES: &str = "\
# where this machine listens
port = 4343
future_setting = \"kept\" # a key this build does not know

# the desk mac
[[clients]]
hostname = \"desk-mac\"
ips = [\"192.0.2.10\"]
position = \"left\" # beside the monitor
future_client_key = 7

[[clients]]
hostname = \"laptop\"
ips = [\"192.0.2.11\"]
position = \"right\"
";

    // LEDGER T4 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_hand_edit_not_yet_read_back_survives_a_save_of_another_field() {
        let (s, mut config) = scratch("handedit", TWO_DEVICES);
        // edited by hand, and not read back
        let edited = TWO_DEVICES
            .replace("port = 4343", "port = 4444")
            .replace("position = \"left\"", "position = \"top\"");
        fs::write(&s.path, &edited).expect("the hand edit");
        // the daemon switches the desk mac on, from its stale memory
        let mut clients = config.clients();
        clients[0].active = true;
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        let desk = entry(&doc, 0);
        assert_eq!(
            text(desk, "activate_on_startup"),
            "true",
            "the daemon's change was not saved:\n{doc}"
        );
        assert_eq!(
            text(desk, "position"),
            "\"top\"",
            "the save put back the position the daemon remembered over the one \
             edited by hand:\n{doc}"
        );
        assert_eq!(
            doc["port"].as_integer(),
            Some(4444),
            "the save put back the port the daemon remembered:\n{doc}"
        );
        assert_eq!(text(entry(&doc, 1), "position"), "\"right\"");
    }

    // LEDGER T5 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn keys_this_build_does_not_know_and_comments_survive_a_save() {
        let (s, mut config) = scratch("unknown", TWO_DEVICES);
        let mut clients = config.clients();
        clients[1].pos = Position::Bottom;
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        let saved = doc.to_string();
        assert_eq!(text(entry(&doc, 1), "position"), "\"bottom\"");
        assert_eq!(
            doc.get("future_setting").and_then(|i| i.as_str()),
            Some("kept"),
            "a key this build does not know was dropped by a save:\n{saved}"
        );
        assert_eq!(
            text(entry(&doc, 0), "future_client_key"),
            "7",
            "a device key this build does not know was dropped by a save:\n{saved}"
        );
        for comment in [
            "# where this machine listens",
            "# a key this build does not know",
            "# the desk mac",
            "# beside the monitor",
        ] {
            assert!(
                saved.contains(comment),
                "the comment {comment:?} was dropped by a save:\n{saved}"
            );
        }
    }

    // LEDGER T6 | class B | 1 error + 4 file on disk: Config::write_back
    #[test]
    fn a_config_that_no_longer_parses_is_left_as_it_is() {
        for (tag, broken) in [
            (
                "syntax",
                "port = 4343\n[[clients]\nhostname = \"desk-mac\"\n",
            ),
            ("type", "port = \"4343\"\n"),
        ] {
            let (s, mut config) = scratch(tag, TWO_DEVICES);
            fs::write(&s.path, broken).expect("an edit in progress");
            let mut clients = config.clients();
            clients[0].active = true;
            config.set_clients(clients);
            let saved = config.write_back();
            assert!(
                saved.is_err(),
                "{tag}: a save over a config that does not parse reported success"
            );
            assert_eq!(
                fs::read_to_string(&s.path).expect("the config"),
                broken,
                "{tag}: a config that does not parse was overwritten, and the edit \
                 in progress with it"
            );
        }
    }

    // LEDGER T7 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn devices_the_daemon_adds_and_removes_change_and_a_hand_added_one_stays() {
        let (s, mut config) = scratch("addremove", TWO_DEVICES);
        let by_hand = "\n[[clients]]\nhostname = \"garage-pc\"\nposition = \"top\"\n";
        fs::write(&s.path, format!("{TWO_DEVICES}{by_hand}")).expect("the hand edit");
        // the daemon removes the desk mac and adds a device
        let mut clients = config.clients();
        clients.remove(0);
        clients.push(ConfigClient {
            label: None,
            ips: HashSet::from(["192.0.2.12".parse().expect("ip")]),
            hostname: None,
            port: DEFAULT_PORT,
            pos: Position::Bottom,
            active: false,
            enter_hook: None,
            fingerprint: Some(DESK.to_string()),
            geometry: None,
        });
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        let names: Vec<String> = doc["clients"]
            .as_array_of_tables()
            .expect("[[clients]]")
            .iter()
            .map(|t| format!("{} {}", text(t, "hostname"), text(t, "ips")))
            .collect();
        assert_eq!(
            names,
            [
                "\"laptop\" [\"192.0.2.11\"]",
                "\"garage-pc\" ",
                " [\"192.0.2.12\"]"
            ],
            "the removed device must go, the one added by hand stay, and the \
             new one be added:\n{doc}"
        );
    }

    // LEDGER T10 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_renamed_device_keeps_what_was_written_into_its_entry_by_hand() {
        // no pin and no address: the rename changes all it can be known by
        let (s, mut config) = scratch(
            "rename",
            "[[clients]]\nhostname = \"garage-pc\" # the old name\nfuture_client_key = 7\n\n\
             [[clients]]\nhostname = \"laptop\"\nposition = \"right\"\n",
        );
        let mut clients = config.clients();
        clients[0].hostname = Some("workshop-pc".to_string());
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        let renamed = entry(&doc, 0);
        assert_eq!(
            text(renamed, "hostname"),
            "\"workshop-pc\"",
            "the renamed device's entry is not where it was:\n{doc}"
        );
        assert_eq!(
            text(renamed, "future_client_key"),
            "7",
            "a rename rewrote the device's entry instead of changing its name:\n{doc}"
        );
        assert!(doc.to_string().contains("# the old name"), "{doc}");
    }

    // LEDGER T11 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_save_never_writes_an_enter_hook_into_the_file() {
        let (s, mut config) = scratch(
            "hook",
            &format!(
                "[[clients]]\nhostname = \"desk-mac\"\nfingerprint = \"{DESK}\"\n\
                 enter_hook = \"from-the-file\"\n"
            ),
        );
        let mut clients = config.clients();
        clients[0].pos = Position::Top;
        clients[0].enter_hook = Some("from-memory".to_string());
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        assert_eq!(text(entry(&doc, 0), "position"), "\"top\"", "{doc}");
        assert_eq!(
            text(entry(&doc, 0), "enter_hook"),
            "\"from-the-file\"",
            "a save wrote a command into the file: the hook is set by editing \
             the file and nowhere else (#56)"
        );
    }

    // LEDGER T174b | class B | 4 file on disk written by Config::write_back, read back by Config
    #[test]
    fn where_a_device_is_drawn_is_saved_into_its_entry_and_read_back() {
        let (s, mut config) = scratch(
            "geometry",
            "[[clients]]\nhostname = \"garage-pc\" # by hand\nposition = \"left\"\n",
        );
        let drawn = Geometry {
            x: 364,
            y: -8,
            width: 96,
            height: 64,
        };
        let mut clients = config.clients();
        clients[0].geometry = Some(drawn);
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        assert_eq!(
            text(entry(&doc, 0), "geometry"),
            "{ x = 364, y = -8, width = 96, height = 64 }",
            "the layout is not written into the device's entry, on one line:\n{doc}"
        );
        assert_eq!(text(entry(&doc, 0), "position"), "\"left\"", "{doc}");
        assert!(doc.to_string().contains("# by hand"), "{doc}");
        config.read_from_disk().expect("the read");
        assert_eq!(
            config.clients()[0].geometry,
            Some(drawn),
            "the saved layout does not read back:\n{doc}"
        );

        // cleared, it goes from the file
        let mut clients = config.clients();
        clients[0].geometry = None;
        config.set_clients(clients);
        config.write_back().expect("the second save");
        let doc = on_disk(&s);
        assert!(
            entry(&doc, 0).get("geometry").is_none(),
            "a cleared layout stayed in the file:\n{doc}"
        );
    }

    // LEDGER T12 | class B | 4 file on disk written by Config::write_back, twice
    #[test]
    fn a_change_once_saved_is_not_written_again_over_a_later_hand_edit() {
        let (s, mut config) = scratch("twice", TWO_DEVICES);
        let mut clients = config.clients();
        clients[1].pos = Position::Bottom;
        config.set_clients(clients.clone());
        config.write_back().expect("the first save");
        // then edited by hand, and not read back
        let edited = fs::read_to_string(&s.path)
            .expect("the config")
            .replace("position = \"bottom\"", "position = \"top\"");
        fs::write(&s.path, edited).expect("the hand edit");
        clients[0].active = true;
        config.set_clients(clients);
        config.write_back().expect("the second save");

        let doc = on_disk(&s);
        assert_eq!(
            text(entry(&doc, 1), "position"),
            "\"top\"",
            "a later save wrote the daemon's earlier change again, over a hand \
             edit made since:\n{doc}"
        );
        assert_eq!(text(entry(&doc, 0), "activate_on_startup"), "true", "{doc}");
    }

    // LEDGER T13 | class B | 4 file on disk written by Config::write_back after Config::read_from_disk
    #[test]
    fn an_edit_read_back_is_what_the_next_save_starts_from() {
        let (s, mut config) = scratch(
            "reread",
            "[[clients]]\nhostname = \"garage-pc\"\n\n[[clients]]\nhostname = \"laptop\"\n",
        );
        // renamed by hand, with a note, and read back
        fs::write(
            &s.path,
            "[[clients]]\nhostname = \"workshop-pc\"\nfuture_client_key = 7\n\n\
             [[clients]]\nhostname = \"laptop\"\n",
        )
        .expect("the hand edit");
        assert!(config.read_from_disk().expect("the reload"));
        let mut clients = config.clients();
        clients[0].pos = Position::Top;
        config.set_clients(clients);
        config.write_back().expect("the save");

        let doc = on_disk(&s);
        assert_eq!(
            text(entry(&doc, 0), "position"),
            "\"top\"",
            "the device's entry is not where it was:\n{doc}"
        );
        assert_eq!(
            text(entry(&doc, 0), "future_client_key"),
            "7",
            "the save compared memory with the file as it was before the reload, \
             and rewrote the device's entry:\n{doc}"
        );
    }

    // LEDGER T8 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn the_trust_cache_is_rewritten_only_when_the_store_changed() {
        let with_cache = format!(
            "{TWO_DEVICES}\n[authorized_fingerprints]\n\"{DESK}\" = \"desk mac\" # since spring\n"
        );
        let (s, mut config) = scratch("cache", &with_cache);
        config.set_authorized_keys(HashMap::from([(DESK.to_string(), "desk mac".to_string())]));
        config.write_back().expect("the save");
        assert!(
            fs::read_to_string(&s.path)
                .expect("the config")
                .contains("# since spring"),
            "an unchanged trust cache was rewritten"
        );

        config.set_authorized_keys(HashMap::new());
        config.write_back().expect("the save");
        let doc = on_disk(&s);
        assert!(
            doc["authorized_fingerprints"]
                .as_table()
                .is_some_and(|t| t.is_empty()),
            "the trust cache must follow the store:\n{doc}"
        );
    }

    const OTHER: &str = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:\
aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

    // LEDGER T15 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn renaming_or_readdressing_a_paired_device_changes_its_entry_in_place() {
        // A new name or address keeps the pin (#99), so the entry is found by
        // it, and the pin is saved with the change.
        let (s, mut config) = scratch(
            "pinrename",
            &format!(
                "[[clients]]\nhostname = \"desk-mac\" # the old name\n\
                 fingerprint = \"{DESK}\"\nfuture_client_key = 7\n\n\
                 [[clients]]\nhostname = \"laptop\"\n"
            ),
        );
        let mut clients = config.clients();
        clients[0].hostname = Some("den".to_string());
        config.set_clients(clients);
        config.write_back().expect("the save");
        let doc = on_disk(&s);
        assert_eq!(
            text(entry(&doc, 0), "hostname"),
            "\"den\"",
            "the renamed paired device's entry is not where it was:\n{doc}"
        );
        assert_eq!(
            text(entry(&doc, 0), "fingerprint"),
            format!("\"{DESK}\""),
            "the renamed paired device's pin was not saved with it:\n{doc}"
        );
        assert_eq!(
            text(entry(&doc, 0), "future_client_key"),
            "7",
            "renaming a paired device rewrote its entry:\n{doc}"
        );
        assert!(doc.to_string().contains("# the old name"), "{doc}");
        assert_eq!(
            doc["clients"].as_array_of_tables().map(|a| a.len()),
            Some(2)
        );

        let text_before = format!(
            "[[clients]]\nips = [\"192.0.2.10\"]\nfingerprint = \"{DESK}\"\n\
             position = \"left\"\n"
        );
        let (s, mut config) = scratch("pinaddr", &text_before);
        // edited by hand, and not read back
        fs::write(&s.path, text_before.replace("\"left\"", "\"top\"")).expect("the hand edit");
        let mut clients = config.clients();
        clients[0].ips = HashSet::from(["192.0.2.20".parse().expect("ip")]);
        config.set_clients(clients);
        config.write_back().expect("the save");
        let doc = on_disk(&s);
        assert_eq!(
            text(entry(&doc, 0), "ips"),
            "[\"192.0.2.20\"]",
            "the new address was not saved:\n{doc}"
        );
        assert_eq!(
            text(entry(&doc, 0), "fingerprint"),
            format!("\"{DESK}\""),
            "the re-addressed paired device's pin was not saved with it:\n{doc}"
        );
        assert_eq!(
            text(entry(&doc, 0), "position"),
            "\"top\"",
            "a new address for a paired device put back the position edited by \
             hand:\n{doc}"
        );
    }

    // LEDGER T9901 | class B | 1 return value: ClientManager::switch_allows_clipboard, 4 file on disk written by Config::write_back and loaded by the next start
    /// A device renamed, re-addressed and switched off stops clipboard with
    /// its machine after a restart as it did before one (#218). The switch
    /// names the machine by the device's pin, and the saved entry lost the pin
    /// with every new name or address, so the next start found an entry that
    /// was off and named no machine.
    #[test]
    fn a_device_edited_and_switched_off_still_stops_clipboard_after_a_restart() {
        use crate::client::{ClientManager, config_entry};
        let (s, mut config) = scratch(
            "editedoff",
            &format!(
                "[[clients]]\nhostname = \"desk-mac\"\nips = [\"192.0.2.10\"]\n\
                 position = \"left\"\nactivate_on_startup = true\nfingerprint = \"{DESK}\"\n"
            ),
        );
        let running = ClientManager::default();
        let desk = running.add_with_config(config.clients().remove(0));
        running.set_hostname(desk, Some("den".to_string()));
        running.set_fix_ips(desk, vec!["192.0.2.20".parse().expect("ip")]);
        assert!(running.deactivate_client(desk), "precondition");
        assert!(
            !running.switch_allows_clipboard(DESK, None),
            "precondition: switched off, the device stops clipboard"
        );
        // as Service::save_config saves it
        let entries = running
            .clients()
            .iter()
            .map(|(c, st)| config_entry(c, st))
            .collect();
        config.set_clients(entries);
        config.write_back().expect("the save");

        let loaded = restarted(&s).clients();
        let fresh = ClientManager::default();
        for entry in loaded.iter().cloned() {
            fresh.add_with_config(entry);
        }
        assert!(
            !fresh.switch_allows_clipboard(DESK, None),
            "a device renamed, re-addressed and switched off let clipboard with \
             its machine through after a restart: the saved entry no longer \
             names the machine. Saved:\n{}",
            fs::read_to_string(&s.path).expect("the config")
        );
        assert_eq!(
            loaded
                .iter()
                .map(|c| (c.hostname.as_deref(), c.active, c.fingerprint.as_deref()))
                .collect::<Vec<_>>(),
            [(Some("den"), false, Some(DESK))],
            "the edit, the switch and the pin did not all survive the restart"
        );
    }

    // LEDGER T9909 | class B | 4 file on disk written by Config::write_back and loaded by the next start
    /// Naming a paired device saves the name in its own key, leaves where it
    /// is dialled and its pin as they were, and the next start reads it back
    /// (#13). The name used to be the hostname.
    #[test]
    fn naming_a_paired_device_saves_its_name_apart_from_its_address() {
        use crate::client::{ClientManager, config_entry};
        let (s, mut config) = scratch(
            "label",
            &format!(
                "[[clients]]\nhostname = \"desk-mac.local\" # where it is\n\
                 fingerprint = \"{DESK}\"\n\n[[clients]]\nhostname = \"laptop\"\n"
            ),
        );
        let running = ClientManager::default();
        let handles: Vec<_> = config
            .clients()
            .into_iter()
            .map(|c| running.add_with_config(c))
            .collect();
        assert!(running.set_label(handles[0], Some(" den ".to_string())));
        let entries = running
            .clients()
            .iter()
            .map(|(c, st)| config_entry(c, st))
            .collect();
        config.set_clients(entries);
        config.write_back().expect("the save");
        let doc = on_disk(&s);
        assert_eq!(
            [
                text(entry(&doc, 0), "label"),
                text(entry(&doc, 0), "hostname"),
                text(entry(&doc, 0), "fingerprint"),
            ],
            [
                "\"den\"".to_string(),
                "\"desk-mac.local\"".to_string(),
                format!("\"{DESK}\""),
            ],
            "(label, hostname, pin) of the named device as saved:\n{doc}"
        );
        assert!(
            doc.to_string().contains("# where it is"),
            "naming the device dropped the comment on its hostname:\n{doc}"
        );
        let loaded = restarted(&s).clients();
        assert_eq!(
            loaded
                .iter()
                .map(|c| (
                    c.label.as_deref(),
                    c.hostname.as_deref(),
                    c.fingerprint.as_deref()
                ))
                .collect::<Vec<_>>(),
            [
                (Some("den"), Some("desk-mac.local"), Some(DESK)),
                (None, Some("laptop"), None)
            ],
            "the name, the address and the pin did not all survive the restart"
        );
    }

    // LEDGER T16 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_change_never_lands_on_an_entry_pinned_to_another_machine() {
        for (tag, id) in [
            ("hostname", "hostname = \"desk-mac\""),
            ("address", "ips = [\"192.0.2.10\"]"),
        ] {
            let (s, mut config) = scratch(
                &format!("apart{tag}"),
                &format!("[[clients]]\n{id}\nfingerprint = \"{DESK}\"\nposition = \"left\"\n"),
            );
            // replaced by hand with another machine known by the same name or
            // address, and not read back
            let other =
                format!("[[clients]]\n{id}\nfingerprint = \"{OTHER}\"\nposition = \"left\"\n");
            fs::write(&s.path, &other).expect("the hand edit");
            let mut clients = config.clients();
            clients[0].pos = Position::Top;
            config.set_clients(clients);
            config.write_back().expect("the save");
            assert_eq!(
                fs::read_to_string(&s.path).expect("the config"),
                other,
                "{tag}: a change to one machine landed on the entry of another \
                 that shares its {tag}"
            );
        }
    }

    // LEDGER T17 | class B | 1 error + 4 file on disk: Config::write_back
    #[test]
    fn devices_written_as_plain_arrays_are_left_as_they_are() {
        // `TomlClient` also reads from an array of its fields in order.
        let positional = "clients = [ [\"desk-mac\", \"desk-mac\", [\"192.0.2.10\"], 4242, \
                          \"left\", false, \"x\"] ]\n";
        for tag in ["remove", "change"] {
            let (s, mut config) = scratch(&format!("plain{tag}"), positional);
            assert_eq!(config.clients().len(), 1, "the device did not load");
            let mut clients = config.clients();
            if tag == "remove" {
                clients.clear();
            } else {
                clients[0].pos = Position::Top;
            }
            config.set_clients(clients);
            let saved = config.write_back();
            assert!(
                saved.is_err(),
                "{tag}: a save that cannot edit the file reported success"
            );
            assert_eq!(
                fs::read_to_string(&s.path).expect("the config"),
                positional,
                "{tag}: devices the save could not edit were changed or dropped"
            );
        }
    }

    // LEDGER T18 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_rewritten_entry_carries_only_a_hook_the_file_still_holds() {
        // Renamed and moved at once: two changes, so the entry is not
        // recognised and is written again from memory.
        let with_hook = format!(
            "[[clients]]\nhostname = \"desk-mac\"\nfingerprint = \"{DESK}\"\n\
             enter_hook = \"run-me\"\n"
        );
        for (tag, deleted_by_hand) in [("kept", false), ("deleted", true)] {
            let (s, mut config) = scratch(&format!("rehook{tag}"), &with_hook);
            if deleted_by_hand {
                // not read back
                fs::write(
                    &s.path,
                    format!("[[clients]]\nhostname = \"desk-mac\"\nfingerprint = \"{DESK}\"\n"),
                )
                .expect("the hand edit");
            }
            let mut clients = config.clients();
            clients[0].hostname = Some("den".to_string());
            clients[0].pos = Position::Top;
            clients[0].fingerprint = None;
            config.set_clients(clients);
            config.write_back().expect("the save");
            let saved = fs::read_to_string(&s.path).expect("the config");
            assert!(
                saved.contains("\"den\""),
                "{tag}: the rename was not saved:\n{saved}"
            );
            assert_eq!(
                saved.contains("run-me"),
                !deleted_by_hand,
                "{tag}: a save wrote a hook the file does not hold, or dropped one \
                 it does (#56):\n{saved}"
            );
        }
    }

    // LEDGER T19 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn the_revocation_cache_is_rewritten_only_when_the_store_changed() {
        let old = RevokedEntry {
            label: "old laptop".to_string(),
            revoked_at: 5,
        };
        let (s, mut config) = scratch(
            "revcache",
            &format!(
                "{TWO_DEVICES}\n[revoked_fingerprints.\"{DESK}\"] # since spring\n\
                 label = \"old laptop\"\nrevoked_at = 5\n"
            ),
        );
        config.set_revoked_fingerprints(HashMap::from([(DESK.to_string(), old.clone())]));
        config.write_back().expect("the save");
        assert!(
            fs::read_to_string(&s.path)
                .expect("the config")
                .contains("# since spring"),
            "an unchanged revocation cache was rewritten"
        );

        let both = HashMap::from([
            (DESK.to_string(), old),
            (
                OTHER.to_string(),
                RevokedEntry {
                    label: "den".to_string(),
                    revoked_at: 9,
                },
            ),
        ]);
        config.set_revoked_fingerprints(both.clone());
        config.write_back().expect("the save");
        let saved: ConfigToml =
            toml_edit::de::from_str(&fs::read_to_string(&s.path).expect("the config"))
                .expect("the saved config parses");
        assert_eq!(
            saved.revoked_fingerprints,
            Some(both),
            "the revocation cache must follow the store"
        );
        assert_eq!(saved.clients.map(|c| c.len()), Some(2));
    }

    // LEDGER T20 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_device_removed_by_hand_stays_removed_when_the_daemon_changed_it() {
        let (s, mut config) = scratch("gone", TWO_DEVICES);
        // the laptop removed by hand, and not read back
        let cut = TWO_DEVICES
            .find("\n[[clients]]\nhostname = \"laptop\"")
            .expect("the laptop's entry");
        fs::write(&s.path, &TWO_DEVICES[..cut]).expect("the hand edit");
        let mut clients = config.clients();
        clients[1].pos = Position::Bottom;
        config.set_clients(clients);
        config.write_back().expect("the save");
        let doc = on_disk(&s);
        assert_eq!(
            doc["clients"].as_array_of_tables().map(|a| a.len()),
            Some(1),
            "a device removed from the file by hand was written back:\n{doc}"
        );
        assert_eq!(text(entry(&doc, 0), "hostname"), "\"desk-mac\"");
    }

    // LEDGER T25 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn an_entry_that_replaced_a_device_by_hand_is_never_changed_or_removed() {
        let pinned = format!(
            "[[clients]]\nhostname = \"desk-mac\"\nfingerprint = \"{DESK}\"\n\
             position = \"left\"\n"
        );
        let unpinned = "[[clients]]\nhostname = \"desk-mac\"\nposition = \"left\"\n";
        // Each file loses the desk mac to another device by hand, and is not
        // read back; the daemon then changes the desk mac from memory.
        type Change = fn(&mut Vec<ConfigClient>);
        let cases: [(&str, &str, Change); 3] = [
            ("moved", &pinned, |c| c[0].pos = Position::Top),
            ("pinned", unpinned, |c| {
                c[0].fingerprint = Some(DESK.to_string())
            }),
            ("removed", unpinned, |c| c.clear()),
        ];
        let other = "[[clients]]\nhostname = \"den\"\nposition = \"left\"\n";
        let mut changed = vec![];
        for (tag, before, change) in cases {
            let (s, mut config) = scratch(&format!("replaced{tag}"), before);
            fs::write(&s.path, other).expect("the hand edit");
            let mut clients = config.clients();
            change(&mut clients);
            config.set_clients(clients);
            config.write_back().expect("the save");
            let saved = fs::read_to_string(&s.path).expect("the config");
            if saved != other {
                changed.push(format!("{tag}:\n{saved}"));
            }
        }
        assert!(
            changed.is_empty(),
            "a save for the desk mac changed den, the device that replaced it \
             by hand: {changed:#?}"
        );
    }

    // LEDGER T28 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_comment_above_a_key_the_daemon_changes_stays_above_it() {
        let entry = "[[clients]]\n# the garage machine\n\
                     hostname = \"garage-pc\" # after the name\n\
                     # keep it on the left\nposition = \"left\"\n";
        let pinned = format!(
            "[[clients]]\n# the garage machine\n\
             hostname = \"garage-pc\" # after the name\nfingerprint = \"{DESK}\"\n\
             # keep it on the left\nposition = \"left\"\n"
        );
        type Change = fn(&mut Vec<ConfigClient>);
        let cases: [(&str, &str, Change, &str); 3] = [
            (
                "renamed",
                entry,
                |c| c[0].hostname = Some("workshop-pc".to_string()),
                "[[clients]]\n# the garage machine\n\
                 hostname = \"workshop-pc\" # after the name\n\
                 # keep it on the left\nposition = \"left\"\n",
            ),
            (
                "moved",
                entry,
                |c| c[0].pos = Position::Top,
                "[[clients]]\n# the garage machine\n\
                 hostname = \"garage-pc\" # after the name\n\
                 # keep it on the left\nposition = \"top\"\n",
            ),
            // revoking the machine forgets the pin, so its line goes
            (
                "pinned",
                &pinned,
                |c| {
                    c[0].hostname = Some("workshop-pc".to_string());
                    c[0].fingerprint = None;
                },
                "[[clients]]\n# the garage machine\n\
                 hostname = \"workshop-pc\" # after the name\n\
                 # keep it on the left\nposition = \"left\"\n",
            ),
        ];
        let mut wrong = vec![];
        for (tag, before, change, after) in cases {
            let (s, mut config) = scratch(&format!("above{tag}"), before);
            let mut clients = config.clients();
            change(&mut clients);
            config.set_clients(clients);
            config.write_back().expect("the save");
            let saved = fs::read_to_string(&s.path).expect("the config");
            if saved != after {
                wrong.push(format!("{tag}:\n{saved}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "a save dropped a comment of an entry it changed, or moved it: {wrong:#?}"
        );
    }

    // LEDGER T29 | class B | 4 file on disk written by Config::write_back
    #[test]
    fn a_comment_above_a_table_written_inline_stays_when_a_save_rewrites_it() {
        const TRUST: &str = "# who may drive this machine\n";
        const DEVICES: &str = "# the machines beside this one\n";
        const REVOKED: &str = "# revoked devices\n";
        type Change = fn(&mut Config);
        fn revoke_another(c: &mut Config) {
            c.set_revoked_fingerprints(HashMap::from([
                (
                    DESK.to_string(),
                    RevokedEntry {
                        label: "old".to_string(),
                        revoked_at: 5,
                    },
                ),
                (
                    OTHER.to_string(),
                    RevokedEntry {
                        label: "older".to_string(),
                        revoked_at: 6,
                    },
                ),
            ]))
        }
        let cases: [(&str, String, Change, String); 5] = [
            (
                "trust",
                format!(
                    "port = 4343\n{TRUST}authorized_fingerprints = {{ \"{DESK}\" = \"desk\" }}\n"
                ),
                |c| {
                    c.set_authorized_keys(HashMap::from([
                        (DESK.to_string(), "desk".to_string()),
                        (OTHER.to_string(), "den".to_string()),
                    ]))
                },
                format!("{TRUST}[authorized_fingerprints]\n"),
            ),
            (
                "devices",
                format!(
                    "{DEVICES}clients = [ {{ hostname = \"desk-mac\", position = \"left\" }} ]\n"
                ),
                |c| {
                    let mut clients = c.clients();
                    clients[0].pos = Position::Top;
                    c.set_clients(clients);
                },
                format!("{DEVICES}[[clients]]\n"),
            ),
            (
                "none",
                format!("{DEVICES}clients = []\n"),
                |c| {
                    let mut clients = c.clients();
                    clients.push(ConfigClient {
                        label: None,
                        ips: HashSet::new(),
                        hostname: Some("desk-mac".to_string()),
                        port: DEFAULT_PORT,
                        pos: Position::Left,
                        active: false,
                        enter_hook: None,
                        fingerprint: None,
                        geometry: None,
                    });
                    c.set_clients(clients);
                },
                format!("{DEVICES}[[clients]]\n"),
            ),
            (
                "revoked",
                format!(
                    "port = 4343\n{REVOKED}revoked_fingerprints = {{ \"{DESK}\" = {{ label = \"old\", revoked_at = 5 }} }}\n"
                ),
                revoke_another,
                format!("{REVOKED}[revoked_fingerprints]\n"),
            ),
            (
                "revoked-header",
                format!(
                    "port = 4343\n{REVOKED}[revoked_fingerprints]\n[revoked_fingerprints.\"{DESK}\"]\nlabel = \"old\"\nrevoked_at = 5\n"
                ),
                revoke_another,
                format!("{REVOKED}[revoked_fingerprints]\n"),
            ),
        ];
        let mut wrong = vec![];
        for (tag, before, change, above) in cases {
            let (s, mut config) = scratch(&format!("inline{tag}"), &before);
            change(&mut config);
            config.write_back().expect("the save");
            let saved = fs::read_to_string(&s.path).expect("the config");
            if !saved.contains(&above) {
                wrong.push(format!("{tag}:\n{saved}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "a save that rewrote a table written inline dropped the comment \
             above it: {wrong:#?}"
        );
    }
}
