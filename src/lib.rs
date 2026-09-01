mod capture;
pub mod capture_test;
pub mod client;
mod clipboard;
pub mod config;
mod connect;
mod crypto;
mod dns;
mod emulation;
pub mod emulation_test;
mod hop_log;
mod listen;
pub mod service;
mod transport;

#[cfg(test)]
mod toolchain_pin {
    //! `rust-toolchain.toml` and the workflows must name the same compiler.
    //!
    //! The pin exists because CI ran `@stable` (unpinned) with
    //! `RUSTFLAGS: -D warnings`, so a Rust release could redden `main` with no
    //! repo change — and did move underneath a run on 2026-09-01
    //! (`stable-aarch64-apple-darwin updated ... from rustc 1.97.1`).
    //!
    //! A pin in two places that can disagree is worse than no pin, because it
    //! reads as pinned while the workflow silently installs something else. So
    //! bumping the version means changing every site in the same commit, and
    //! this fails until they agree.

    fn pinned_channel() -> String {
        const TOML: &str = include_str!("../rust-toolchain.toml");
        TOML.lines()
            .map(|l| l.split('#').next().unwrap_or("")) // drop comments
            .find_map(|l| l.trim().strip_prefix("channel").map(str::to_string))
            .and_then(|l| {
                l.split('=')
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
            .expect("rust-toolchain.toml must set channel = \"<version>\"")
    }

    #[test]
    fn every_workflow_names_the_pinned_toolchain() {
        let want = pinned_channel();
        assert!(
            want.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "the pin must be an explicit version, not a moving channel like \
             {want:?} — a moving channel is what this guard exists to prevent"
        );
        for (name, yml) in [
            ("check.yml", include_str!("../.github/workflows/check.yml")),
            (
                "release.yml",
                include_str!("../.github/workflows/release.yml"),
            ),
        ] {
            let uses: Vec<&str> = yml
                .lines()
                .map(str::trim)
                .filter(|l| l.contains("dtolnay/rust-toolchain@"))
                .collect();
            assert!(
                !uses.is_empty(),
                "{name} no longer installs a toolchain — this guard is testing nothing"
            );
            for u in uses {
                let got = u.rsplit('@').next().unwrap_or("");
                assert_eq!(
                    got, want,
                    "{name} installs {got:?} but rust-toolchain.toml pins {want:?}. \
                     Bump both in the same commit; a pin that disagrees with the \
                     workflow reads as pinned while building with something else."
                );
            }
        }
    }
}
