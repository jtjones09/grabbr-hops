//! Run the DAEMON's own discovery, with debug logging, and print what it sees.
//!
//! The existing `discovery_probe` builds its own mDNS browser. That proves the
//! network works, which is useful, but it is why #149 stayed unpinned for weeks:
//! the probe finding peers while the daemon finds none tells you the fault is
//! somewhere in between, and nothing narrowed it further.
//!
//! This uses `hops::discovery::Discovery` — the exact type the daemon runs — so
//! whatever it does here is what the daemon does. The debug lines inside
//! `classify` and `pump` say which filter drops an announcement, if one does.
//!
//! Announces under a distinct instance name so it cannot collide with a running
//! daemon's advertisement.
//!
//!   cargo run -q -p hops --example discovery_daemon_probe

use std::time::Duration;

use hops::discovery::Discovery;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    unsafe {
        std::env::set_var("RUST_LOG", "hops::discovery=debug");
    }
    env_logger::builder().format_timestamp(None).init();

    // A fingerprint that is ours, so self-echo suppression is exercised as the
    // daemon exercises it — but distinct from any real machine's.
    let ours = (0..32)
        .map(|_| "ab".to_string())
        .collect::<Vec<_>>()
        .join(":");

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let Some(mut d) = Discovery::new(true, 4242, &ours, "hops-daemon-probe") else {
                eprintln!("Discovery::new returned None — discovery could not start at all.");
                return;
            };
            eprintln!("running the daemon's discovery for 20s; debug lines show every filter\n");

            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            let mut found = 0usize;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    e = d.event() => match e {
                        Some(ev) => {
                            found += 1;
                            match ev {
                                hops::discovery::DiscoveryEvent::Found(p) => eprintln!(
                                    "EVENT {found}: FOUND {:?} at {:?} claiming {:?}",
                                    p.label, p.addrs, p.claimed_fingerprint
                                ),
                                hops::discovery::DiscoveryEvent::Lost(l) => {
                                    eprintln!("EVENT {found}: LOST {l:?}")
                                }
                            }
                        }
                        None => { eprintln!("the discovery channel closed"); break; }
                    },
                }
            }
            eprintln!("\n{found} event(s) reached the service loop");
            d.terminate().await;
        })
        .await;
}
