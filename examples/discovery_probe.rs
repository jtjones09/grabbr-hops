//! Prove LAN discovery works, on real hardware, without starting a daemon.
//!
//! `Discovery` only touches mDNS — it never binds the QUIC port — so this runs
//! safely alongside a hops daemon that already owns 4242.
//!
//! Run it on two machines at once: each should list the other. That is the
//! check that matters and the one a single machine cannot make, because a
//! single host resolves its own announcement through the loopback path and
//! proves only that the library links.
//!
//!     cargo run --example discovery_probe
//!     cargo run --example discovery_probe -- --fingerprint aa:bb:cc --name my-box
use std::time::Duration;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str, d: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| d.to_string())
    };
    let fp = arg("--fingerprint", "probe:00:00:00");
    let name = arg(
        "--name",
        &hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "probe".into()),
    );
    let secs: u64 = arg("--seconds", "20").parse().unwrap_or(20);

    println!("announcing as {name:?} with fingerprint {fp}; listening {secs}s");
    println!("run this on a SECOND machine at the same time — each should list the other\n");

    let local = tokio::task::LocalSet::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(local.run_until(async move {
        let Some(mut d) = hops::discovery::Discovery::new(true, 4242, &fp, &name) else {
            println!("discovery did not start — see the log above");
            return;
        };
        // Apply the SAME keying and merge the service does, so what prints is
        // what the device list would show — not the raw announcement stream.
        // mDNS re-announces per interface with partial address sets; showing
        // those raw made one machine look like several.
        let mut peers: std::collections::HashMap<String, hops::discovery::DiscoveredPeer> =
            Default::default();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                ev = d.event() => match ev {
                    Some(hops::discovery::DiscoveryEvent::Found(p)) => {
                        let key = hops::discovery::peer_key(&p);
                        let changed = match peers.get_mut(&key) {
                            Some(known) => hops::discovery::merge(known, p),
                            None => { peers.insert(key.clone(), p); true }
                        };
                        if changed {
                            let p = &peers[&key];
                            println!(
                                "PEER   {:<24} claims {:<20} at {:?}",
                                p.label,
                                p.claimed_fingerprint.as_deref().unwrap_or("(nothing)"),
                                p.addrs
                            );
                        }
                    }
                    Some(hops::discovery::DiscoveryEvent::Lost(l)) => {
                        peers.retain(|_, p| p.label != l);
                        println!("LOST   {l}");
                    }
                    None => break,
                },
            }
        }
        d.terminate().await;
        println!("\n--- what the device list would show ---");
        for p in peers.values() {
            println!(
                "  {:<24} {:<20} {:?}",
                p.label,
                p.claimed_fingerprint.as_deref().unwrap_or("(no claim)"),
                p.addrs
            );
        }
        println!(
            "\n{} distinct machine(s). {}",
            peers.len(),
            if peers.is_empty() {
                "Nothing found — expected if no other machine is running this."
            } else {
                "Discovery is working on this network."
            }
        );
    }));
}
