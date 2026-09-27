//! `hops cli` write commands return once the daemon has acted on them, and
//! fail, saying why, when it did not (#6).
//!
//! Runs the built binary twice over: once as the daemon, with dummy capture
//! and emulation, discovery off and every path in a scratch directory, and
//! once per command as `hops cli`, pointed at that directory through its
//! environment. Nothing in this process's own environment changes, so the
//! tests can run side by side.
#![cfg(unix)]

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

struct Daemon {
    child: Child,
    dir: PathBuf,
    config: PathBuf,
    log: PathBuf,
    port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A port nothing listens on, on every address as the daemon binds it: a
/// device there is never reached.
fn free_port() -> u16 {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port()
}

impl Daemon {
    /// Start a daemon whose config is the dummy backends plus `tables`.
    fn start(tag: &str, tables: &str) -> Daemon {
        // Short, for `sun_path` (about 104 bytes on macOS).
        let dir = PathBuf::from(format!("/tmp/h-cw{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let dir = std::fs::canonicalize(&dir).expect("the scratch directory resolves");
        let config_dir = dir.join(".config/lan-mouse");
        std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
        std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
        let config = config_dir.join("config.toml");
        let log = dir.join("daemon.log");
        let (child, port) = common::launch(
            &config,
            |port| {
                format!(
                    "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
                     discovery = false\n\n{tables}"
                )
            },
            &log,
            || {
                Self::hops(&dir, &log)
                    .arg("--config")
                    .arg(&config)
                    .arg("--cert-path")
                    .arg(config_dir.join("lan-mouse.pem"))
                    .arg("daemon")
                    .spawn()
                    .expect("the hops binary starts")
            },
        );
        Daemon {
            child,
            dir,
            config,
            log,
            port,
        }
    }

    /// The hops binary, with an environment that points only at `dir`.
    fn hops(dir: &std::path::Path, log: &std::path::Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_hops"));
        c.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir.join(".config"))
            .env("XDG_STATE_HOME", dir)
            .env("HOPS_LOG_FILE", log)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Run `hops cli <args>` against this daemon and wait for it to exit.
    fn cli(&self, args: &[&str]) -> Output {
        Self::hops(&self.dir, &self.dir.join("cli.log"))
            .arg("cli")
            .args(args)
            .output()
            .expect("hops cli runs")
    }

    /// `hops cli <args>`, reading a config of its own rather than the
    /// daemon's: every hops process parses its config before it starts.
    fn cli_beside(&self, args: &[&str]) -> Output {
        let own = self.dir.join("cli.toml");
        std::fs::write(&own, "").expect("a config for the command");
        Self::hops(&self.dir, &self.dir.join("cli.log"))
            .arg("--config")
            .arg(&own)
            .arg("cli")
            .args(args)
            .output()
            .expect("hops cli runs")
    }

    /// The saved `[[clients]]` entries, as the file holds them now.
    fn saved_clients(&self) -> Vec<toml_edit::Table> {
        let text = std::fs::read_to_string(&self.config).expect("the config");
        let doc: toml_edit::DocumentMut = text.parse().expect("the saved config parses");
        doc.get("clients")
            .and_then(|c| c.as_array_of_tables())
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn saved_text(&self) -> String {
        std::fs::read_to_string(&self.config).expect("the config")
    }

    /// A machine this daemon has never seen asks to pair, and waits: its
    /// fingerprint, once the daemon has admitted the request.
    fn asked_to_pair(&self) -> String {
        // add device, which is what lets a request prompt
        ok(self, &["add-client"]);
        let fp = knock(self.port);
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.log().contains(&format!("fingerprint {fp}")) {
            assert!(
                Instant::now() < deadline,
                "the daemon never admitted the pairing request; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        fp
    }
}

/// Accepts any server certificate: the stranger does not care who answers.
#[derive(Debug)]
struct AnyServer;

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Dial the daemon on `port` once, as a machine it has never seen, and
/// return that machine's fingerprint in the daemon's format. The daemon
/// refuses the handshake; what matters is the request it leaves.
fn knock(port: u16) -> String {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().expect("a key");
    let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
        .expect("params")
        .self_signed(&key)
        .expect("a certificate");
    let fingerprint = Sha256::digest(cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer))
        .with_client_auth_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).expect("the key"),
        )
        .expect("client auth");
    crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("a QUIC client"),
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("an endpoint");
        let at: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        if let Ok(connecting) = endpoint.connect_with(config, at, "grabbr") {
            if let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), connecting).await {
                let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
            }
        }
    });
    fingerprint
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn ok(d: &Daemon, args: &[&str]) {
    let out = d.cli(args);
    assert!(
        out.status.success(),
        "`hops cli {}` failed:\n{}\ndaemon log:\n{}",
        args.join(" "),
        said(&out),
        d.log()
    );
}

/// The value of `key`, without the whitespace and comment around it.
fn value(entry: &toml_edit::Table, key: &str) -> String {
    entry
        .get(key)
        .and_then(|i| i.as_value())
        .map(|v| {
            let mut v = v.clone();
            v.decor_mut().clear();
            v.to_string()
        })
        .unwrap_or_default()
}

const ONE_DEVICE: &str = "[[clients]]\nips = [\"127.0.0.1\"]\nport = {dead}\nposition = \"left\"\n";

/// A machine paired with the daemon's before it started.
const PAIRED: &str = "cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:\
cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd:cd";

fn one_device() -> String {
    ONE_DEVICE.replace("{dead}", &free_port().to_string())
}

// LEDGER T1 | class B | 5 process: hops cli exit code and stderr, against the hops daemon
#[test]
fn a_write_verb_for_a_device_that_does_not_exist_fails_and_says_so() {
    let d = Daemon::start("nodev", &one_device());
    for args in [
        &["activate", "42"][..],
        &["deactivate", "42"],
        &["set-position", "42", "right"],
        &["set-port", "42", "4243"],
        &["set-ips", "42", "127.0.0.1"],
    ] {
        let out = d.cli(args);
        assert!(
            !out.status.success(),
            "`hops cli {}` names no device, and still reported success:\n{}",
            args.join(" "),
            said(&out)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("no device with id 42"),
            "`hops cli {}` failed without saying the device does not exist:\n{}",
            args.join(" "),
            said(&out)
        );
    }
}

// LEDGER T2 | class B | 5 process: hops cli exit code and stderr; the reason comes from the hops daemon
#[test]
fn a_grant_nobody_asked_for_fails_with_the_reason() {
    let d = Daemon::start("grant", "");
    let fp = ["ab"; 32].join(":");
    let out = d.cli(&["authorize-key", "desk mac", &fp, "--controller", "that"]);
    assert!(
        !out.status.success(),
        "no device asked to pair, so nothing was granted, and the command \
         still reported success:\n{}",
        said(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no pairing request"),
        "the refusal did not say why:\n{}",
        said(&out)
    );

    // refused for another reason: a fingerprint that is not one. A device
    // removed here is a stranger again, refused like the one above (#184).
    let gone = ["ef"; 32].join(":");
    ok(&d, &["remove-authorized-key", &gone]);
    for (why, fp) in [
        ("no pairing request", gone.as_str()),
        ("valid", "not-a-fingerprint"),
    ] {
        let out = d.cli(&["authorize-key", "desk mac", fp, "--controller", "that"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && err.contains("not done: nothing was trusted"),
            "a grant the service refused was not reported as refused:\n{}",
            said(&out)
        );
        assert!(
            err.contains(why),
            "the refusal did not say why:\n{}",
            said(&out)
        );
    }
}

// LEDGER T3 | class B | 4 config file written by the hops daemon, read the moment hops cli exits 0
#[test]
fn each_write_verb_is_saved_by_the_time_it_returns() {
    let d = Daemon::start(
        "saved",
        &format!(
            "{}\n[authorized_fingerprints]\n\"{PAIRED}\" = \"desk mac\"\n",
            one_device()
        ),
    );
    assert!(
        d.saved_text().contains(PAIRED),
        "precondition: the paired machine is listed"
    );
    // Checked with no wait at all: a command that returned before the daemon
    // acted leaves the old file here.
    for round in 0..5 {
        let (pos, port) = if round % 2 == 0 {
            ("right", "4301")
        } else {
            ("left", "4302")
        };
        ok(&d, &["set-position", "0", pos]);
        assert_eq!(
            value(&d.saved_clients()[0], "position"),
            format!("\"{pos}\""),
            "round {round}: set-position returned before the change was saved"
        );
        ok(&d, &["set-port", "0", port]);
        assert_eq!(
            value(&d.saved_clients()[0], "port"),
            port,
            "round {round}: set-port returned before the change was saved"
        );
    }

    ok(&d, &["set-ips", "0", "127.0.0.2"]);
    assert_eq!(value(&d.saved_clients()[0], "ips"), "[\"127.0.0.2\"]");

    ok(&d, &["set-host", "0", "localhost"]);
    assert_eq!(value(&d.saved_clients()[0], "hostname"), "\"localhost\"");

    ok(&d, &["activate", "0"]);
    assert_eq!(value(&d.saved_clients()[0], "activate_on_startup"), "true");
    ok(&d, &["deactivate", "0"]);
    assert_ne!(value(&d.saved_clients()[0], "activate_on_startup"), "true");

    ok(&d, &["add-client", "--port", "4303", "--ips", "127.0.0.3"]);
    let added = d.saved_clients();
    assert_eq!(
        added.len(),
        2,
        "add-client returned before the device was saved"
    );
    assert_eq!(value(&added[1], "port"), "4303");
    assert_eq!(value(&added[1], "ips"), "[\"127.0.0.3\"]");

    ok(&d, &["remove-client", "1"]);
    assert_eq!(
        d.saved_clients().len(),
        1,
        "remove-client returned before the removal was saved"
    );

    // Paired at start, from the table a build before the trust store read.
    ok(&d, &["remove-authorized-key", PAIRED]);
    assert!(
        !d.saved_text().contains(PAIRED),
        "remove-authorized-key returned before the removal was saved:\n{}",
        d.saved_text()
    );

    ok(&d, &["save-config"]);
}

// LEDGER T9 | class B | 4 config file written by the hops daemon, on a change made with hops cli
#[test]
fn a_save_by_the_daemon_keeps_what_it_does_not_own() {
    let tables = format!(
        "# a note on this machine\nfuture_setting = \"kept\"\n\n\
         # the desk mac\n{}future_client_key = 7 # a key this build does not know\n",
        one_device()
    );
    let d = Daemon::start("keep", &tables);
    ok(&d, &["set-position", "0", "right"]);
    // Waited for, so this also reads a build whose command returns early.
    let deadline = Instant::now() + Duration::from_secs(10);
    while value(&d.saved_clients()[0], "position") != "\"right\"" {
        assert!(Instant::now() < deadline, "the change was never saved");
        std::thread::sleep(Duration::from_millis(20));
    }
    let saved = d.saved_text();
    for kept in [
        "future_setting = \"kept\"",
        "future_client_key = 7",
        "# a note on this machine",
        "# the desk mac",
        "# a key this build does not know",
    ] {
        assert!(
            saved.contains(kept),
            "a save by the daemon dropped {kept:?}, which it does not own:\n{saved}"
        );
    }
}

// LEDGER T14 | class B | 4 config file left by the hops daemon + 5 hops cli exit code and stderr
#[test]
fn a_save_over_a_config_that_does_not_parse_fails_and_leaves_it() {
    let d = Daemon::start("broken", &one_device());
    let broken = "port = 4343\n[[clients]\nhostname = \"desk-mac\"\n";
    std::fs::write(&d.config, broken).expect("an edit in progress");
    let out = d.cli_beside(&["save-config"]);
    assert_eq!(
        d.saved_text(),
        broken,
        "a save replaced a config that does not parse, and the edit in progress with it"
    );
    assert!(
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("not saved"),
        "the save failed and the command did not say so:\n{}",
        said(&out)
    );
}

// LEDGER T21 | class B | 4 config file written by the hops daemon on hops cli set-host
#[test]
fn renaming_a_paired_device_keeps_its_entry_in_place() {
    // Pinned, and known by its name alone. The daemon drops a pin its trust
    // store does not know, and a rename forgets it too: either way memory
    // holds no pin where the file has one.
    let pin = ["ab"; 32].join(":");
    let tables = format!(
        "[[clients]]\nhostname = \"desk-mac\" # the old name\nfingerprint = \"{pin}\"\n\
         future_client_key = 7\n\n{}",
        one_device()
    );
    let d = Daemon::start("pinname", &tables);
    ok(&d, &["set-host", "0", "den"]);
    let clients = d.saved_clients();
    assert_eq!(
        value(&clients[0], "hostname"),
        "\"den\"",
        "the renamed device's entry is not where it was:\n{}",
        d.saved_text()
    );
    assert_eq!(
        value(&clients[0], "future_client_key"),
        "7",
        "renaming a paired device rewrote its entry:\n{}",
        d.saved_text()
    );
    assert!(
        d.saved_text().contains("# the old name"),
        "{}",
        d.saved_text()
    );
}

// LEDGER T22 | class B | 5 process: hops cli exit code and output, after a grant the hops daemon made
#[test]
fn a_grant_made_is_reported_made_when_the_config_is_not_saved() {
    let d = Daemon::start("grantok", "");
    let fp = d.asked_to_pair();
    // an edit in progress: the config the daemon copies trust into does not parse
    std::fs::write(&d.config, "port = 4343\n[[clients]\n").expect("an edit in progress");
    let out = d.cli_beside(&["authorize-key", "laptop", &fp, "--controller", "that"]);
    let text = said(&out);
    assert!(
        !text.contains("nothing was trusted") && !text.contains("not trusted"),
        "the device was trusted, and the command said it was not:\n{text}"
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains(&fp),
        "the grant was made and saved in the trust store, and the command did \
         not report it:\n{text}\ndaemon log:\n{}",
        d.log()
    );
}

/// Makes a directory read-only until dropped.
struct ReadOnly(PathBuf);

impl ReadOnly {
    fn new(dir: PathBuf) -> Option<ReadOnly> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        let guard = ReadOnly(dir);
        // Some users write anyway (root): nothing to test then.
        let probe = guard.0.join("probe");
        if std::fs::write(&probe, "").is_ok() {
            let _ = std::fs::remove_file(&probe);
            return None;
        }
        Some(guard)
    }
}

impl Drop for ReadOnly {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

// LEDGER T23 | class B | 5 process: hops cli exit code and output, after a grant the hops daemon could not save
#[test]
fn a_grant_the_trust_store_could_not_save_fails_and_says_it_is_in_effect() {
    let d = Daemon::start("grantro", "");
    let fp = d.asked_to_pair();
    let Some(_read_only) = ReadOnly::new(d.config.parent().expect("dir").to_path_buf()) else {
        eprintln!("this user writes to read-only directories: skipped");
        return;
    };
    let out = d.cli_beside(&["authorize-key", "laptop", &fp, "--controller", "that"]);
    let text = said(&out);
    assert!(
        !text.contains("nothing was trusted"),
        "the device was trusted until a restart, and the command said nothing \
         was:\n{text}"
    );
    assert!(
        !out.status.success() && text.contains("not saved: the change is in effect"),
        "a grant the trust store could not save was reported saved:\n{text}"
    );
}

// LEDGER T24 | class B | 5 process: hops cli exit code and stderr; the notice comes from the hops daemon
#[test]
fn a_device_change_that_was_not_saved_fails_and_says_so() {
    let d = Daemon::start("unsaved", &one_device());
    std::fs::write(&d.config, "port = 4343\n[[clients]\n").expect("an edit in progress");
    let out = d.cli_beside(&["set-position", "0", "right"]);
    assert!(
        !out.status.success()
            && String::from_utf8_lossy(&out.stderr).contains("not saved: the change is in effect"),
        "a change the daemon could not save was reported saved:\n{}",
        said(&out)
    );
}
