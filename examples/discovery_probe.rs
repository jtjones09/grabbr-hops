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
    // Debug by default for the discovery module: a probe that says nothing when
    // it finds nothing is unfalsifiable. Rejections and raw mDNS events are the
    // whole point of running this.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,hops::discovery=debug"),
    )
    .init();
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str, d: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| d.to_string())
    };
    let name = arg(
        "--name",
        &hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "probe".into()),
    );
    // Derive the default fingerprint FROM THE NAME so two machines never share
    // one. A fixed default (`probe:00:00:00`) made every probe look like every
    // other probe's own echo, so each machine silently discarded the other and
    // printed nothing — while still printing LOST on withdrawal, because
    // removals are not filtered. That produced "they cannot see each other"
    // when discovery was in fact working perfectly.
    let default_fp = {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a, enough to disambiguate
        for b in name.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        h.to_be_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let fp = arg("--fingerprint", &default_fp);
    let secs: u64 = arg("--seconds", "20").parse().unwrap_or(20);

    // Say what WE are announcing, so a one-sided run still tells you which
    // interfaces this machine is putting on the wire.
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        println!("this machine's addresses:");
        for i in ifs.iter().filter(|i| !i.is_loopback()) {
            println!("   {:<12} {}", i.name, i.ip());
        }
    }
    println!("\nannouncing as {name:?} with fingerprint {fp}; listening {secs}s");
    println!("(the fingerprint is derived from the name, so two machines differ)");
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
        // Labels that withdrew before we finished. Reported, not deleted.
        let mut withdrawn: std::collections::HashSet<String> = Default::default();
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
                        // Withdrawn, but STILL SEEN. Dropping it from the summary
                        // made a peer that merely exited first read as "nothing
                        // found", which is the opposite of what happened.
                        withdrawn.insert(l.clone());
                        println!("LOST   {l}  (stopped announcing — still counts as seen)");
                    }
                    None => break,
                },
            }
        }
        d.terminate().await;
        println!("\n--- every machine seen during this run ---");
        for p in peers.values() {
            println!(
                "  {:<24} {:<20} {:?}{}",
                p.label,
                p.claimed_fingerprint.as_deref().unwrap_or("(no claim)"),
                p.addrs,
                if withdrawn.contains(&p.label) {
                    "   [stopped before we did]"
                } else {
                    ""
                }
            );
        }
        println!(
            "\n{} distinct machine(s) seen. {}",
            peers.len(),
            if peers.is_empty() {
                "Nothing found. If the other machine printed LOST for THIS one, \
                 multicast is fine and something filtered it — re-run and read the \
                 DEBUG lines for the reason."
            } else {
                "Discovery is working on this network."
            }
        );
    }));
}
