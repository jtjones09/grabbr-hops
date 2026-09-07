//! The sink writes a real file, whoever started the process.
//!
//! The unit tests in `src/logging.rs` cover the filter and the rotation rule in
//! isolation. This covers the thing that actually broke: a process whose output
//! went nowhere. The Windows tray is launched from a VBS wrapper that redirects
//! nothing, so every line it logged — including the backtrace its panic hook
//! force-captured — was written to a handle nobody was reading. No amount of
//! correct filtering helps if the bytes never land.
//!
//! An integration test gets its own process, which is what makes this testable
//! at all: `init()` installs a global logger and can only run once.

use std::io::Read;

#[test]
fn a_line_reaches_the_file_with_no_help_from_whoever_launched_us() {
    let path = std::env::temp_dir().join(format!("hops-sink-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::env::set_var("HOPS_LOG_FILE", &path);
    // A bare level, the way a launcher sets it.
    std::env::set_var("HOPS_LOG_LEVEL", "debug");

    hops::logging::init("test");

    log::info!(target: "hops::service", "a line from hops itself");
    log::debug!(target: "mdns_sd", "a packet from a dependency");
    // Deliberately NOT flushed. The release profile is `panic = "abort"`, so
    // the panic hook's line is written microseconds before the process is
    // killed with no unwinding and no destructors — a buffered writer would
    // drop exactly the line worth having. Reading it back with no flush is what
    // holds that open against someone later wrapping the file in a BufWriter.

    let mut written = String::new();
    std::fs::File::open(&path)
        .expect(
            "the process must open its own log. The Windows tray had no \
             redirection at all, so its output — panic backtraces included — \
             went to a handle nobody was reading.",
        )
        .read_to_string(&mut written)
        .expect("read");

    assert!(
        written.contains("a line from hops itself"),
        "hops' own line must be on disk without an explicit flush. Under \
         `panic = \"abort\"` nothing runs after the panic hook, so a buffered \
         sink loses the backtrace it just captured. Got: {written:?}"
    );
    assert!(
        !written.contains("a packet from a dependency"),
        "a bare `debug` must not turn on every dependency. One of them logs \
         each mDNS packet, which is how a log file reached 5.2 GB. Got: {written:?}"
    );
    let _ = std::fs::remove_file(&path);
}
