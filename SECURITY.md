# Security policy

## Reporting a vulnerability

Report it privately, through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**
(<https://github.com/jtjones09/grabbr-hops/security/advisories/new>).
Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Include what you can of:

- the version (`hops --version`) and the operating systems involved;
- what an attacker needs: a position on the network, a paired device, a local
  account on the machine;
- steps to reproduce, or a proof of concept;
- the impact.

The report and its discussion stay private in the advisory until a fixed
release is published, and the advisory is published with it.

## Supported versions

Security fixes go into the next release. Only the latest release is
supported; fixes are not backported, so update to the latest release.

## Scope

In scope:

- the `hops` binary: the daemon, the GUI, the terminal UI and the CLI;
- the network protocol: the QUIC and TLS handshake, pairing, trust and
  revocation, and anything a peer can do before or beyond what it was
  trusted for;
- the channel between the daemon and its frontends, and the configuration,
  key and token files hops writes;
- the release artifacts and the workflow that builds them, and the install
  scripts and service definitions in this repository.

Out of scope:

- what a trusted peer is designed to do: a paired machine allowed to control
  this one moves its cursor and types on it;
- attacks that need the same user's account, or administrator rights, on the
  machine running hops;
- vulnerabilities in a dependency that hops does not reach. Report those to
  the dependency; report them here too if hops is affected.

## Security model

[docs/SECURITY.md](docs/SECURITY.md) states what pairing protects against,
what it cannot protect against, and how to remove a machine or recover one.

## Verifying a release

`SHA256SUMS` in each release holds the SHA-256 of every other asset, and
every asset has a build-provenance attestation from the release workflow.
Check the attestation against that workflow and the tag of the release
downloaded, `v0.13.0` below: without `--signer-workflow` and
`--source-ref`, an attestation from any workflow run in the repository, on
any branch, passes.

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS
gh attestation verify hops-linux-x86_64.tar.gz --repo jtjones09/grabbr-hops \
  --signer-workflow jtjones09/grabbr-hops/.github/workflows/release.yml \
  --source-ref refs/tags/v0.13.0
```

Each archive, and the app in the dmg, holds `LICENSE`,
`THIRD-PARTY-NOTICES.txt` and a CycloneDX SBOM (`hops-<target>.cdx.json`)
for each target its binary is built for; the SBOMs are also release assets.
Each binary embeds the list of crates it was built from, which
`cargo audit bin` reads.
