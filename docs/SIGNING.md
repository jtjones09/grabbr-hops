# Signing the macOS and Windows builds

The macOS build is signed and notarized as described first; the Windows build
is Authenticode-signed as described under [Windows](#windows).

## macOS

Goal: ship a macOS `.app` in a `.dmg` that opens with **no Gatekeeper warning** —
double-click → "hops is from an identified developer" → runs, offline, no
`xattr` dance. This needs an Apple Developer account (paid) and a one-time setup.

### What you need to gather (once)

1. **Developer ID Application certificate** — the identity that signs apps for
   distribution *outside* the App Store.
   - Xcode → Settings → Accounts → your team → **Manage Certificates** → **+** →
     **Developer ID Application** (or create it in the developer portal).
   - It lands in your **login keychain**. Confirm with:
     ```sh
     security find-identity -v -p codesigning
     ```
     Copy the full name, e.g. `Developer ID Application: Jane Doe (AB12CD34EF)`.

2. **App Store Connect API key** (for notarization — recommended over a password).
   - App Store Connect → **Users and Access → Integrations → Keys** → **+** →
     name it, role **Developer** → **Generate**.
   - **Download the `.p8` — you only get one chance.** Note the **Key ID**
     (in the table) and the **Issuer ID** (above the table).

3. Your **Team ID** — the 10-char code in the identity above / the portal
   membership page.

### Sign locally

```sh
# 1. build the universal binary (or use CI's), then assemble the bundle:
cargo build --release --no-default-features --features "tui slint"
scripts/package-macos.sh target/release/hops        # → dist/hops.app + dist/hops-macos.dmg (unsigned)

# 2. sign + notarize + staple (fill in your identity + key):
DEVELOPER_ID="Developer ID Application: Jane Doe (AB12CD34EF)" \
NOTARY_KEY=~/keys/AuthKey_XXXXXXXXXX.p8 \
NOTARY_KEY_ID=XXXXXXXXXX \
NOTARY_ISSUER=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
scripts/sign-macos.sh                                # → signed+notarized+stapled dist/hops-macos.dmg
```

Prefer a keychain profile? Create it once and skip the key envs:
```sh
xcrun notarytool store-credentials hops-notary \
  --key ~/keys/AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --issuer <issuer-id>
DEVELOPER_ID="Developer ID Application: … (TEAMID)" NOTARY_PROFILE=hops-notary scripts/sign-macos.sh
```

`sign-macos.sh` prints a Gatekeeper assessment at the end — success looks like
`accepted` / `source=Notarized Developer ID`.

### In CI (GitHub Actions)

`release.yml` signs and notarizes the macOS `.dmg` in its own job,
`sign-macos`. That job runs no `cargo`: it receives only the unsigned universal
build from the build job (the binary, `LICENSE`, `THIRD-PARTY-NOTICES.txt` and
the SBOMs, which go into the app's `Contents/Resources`), bundles it with
`package-macos.sh`, signs it with
`sign-macos.sh`, and checks the result with `verify-macos-release.sh` before
uploading it. The build job compiles every dependency's build script and proc
macro, so no secret is visible there.

Only `sign-macos` names the **`macos-signing` environment**, and the
secrets belong there. The workflow cannot enforce this itself: GitHub
creates an environment a job names without any protection, and
repository-level secrets are readable by every job in every workflow, on
any branch. Set it up once, before the first release that signs:

1. Settings → Environments → `macos-signing` (create it if it is not
   there) → Deployment branches and tags → Selected branches and tags:
   add the tag rule `v*` and the branch rule `release/*`.
2. Add the six secrets below as environment secrets there.
3. Delete the repository-level `MACOS_*` secrets of the same names
   (Settings → Secrets and variables → Actions).

Until all three are done, a run from any branch can read the signing
secrets.

| secret | what |
| --- | --- |
| `MACOS_CERT_P12` | the Developer ID cert exported from Keychain as `.p12`, base64-encoded (`base64 -i cert.p12`) |
| `MACOS_CERT_PASSWORD` | the password you set when exporting the `.p12` |
| `MACOS_DEVELOPER_ID` | the identity string, e.g. `Developer ID Application: Jane Doe (AB12CD34EF)` |
| `MACOS_NOTARY_KEY` | the `.p8` contents, base64-encoded (`base64 -i AuthKey_XXXX.p8`) |
| `MACOS_NOTARY_KEY_ID` | the Key ID |
| `MACOS_NOTARY_ISSUER` | the Issuer ID |

`sign-macos` fails when any of the six is missing, on every run. A tag whose
run cannot produce a verified dmg publishes nothing, and the publish job
refuses a release that lacks any of its assets or whose assets do not match
`SHA256SUMS`.

To get a signed dmg without releasing, run the workflow by hand (Actions →
release → Run workflow) from a `release/*` branch or a `v*` tag. Every job
except publish runs, and the dmg is attached to the run as the
`hops-macos-universal-dmg` artifact. Once the environment is limited to
those refs as above, a run from any other branch stops at `sign-macos`
without reading a secret.

`verify-macos-release.sh` passes only when `spctl` reports
`source=Notarized Developer ID` for the dmg and for the app inside it, both
carry a stapled ticket, the app is signed as `com.grabbr.hops` by team
`9V42Q953X9` (`TeamIdentifier` in `codesign -dv`), and it carries
its licence, notices, an SBOM per target and a binary built with
`cargo auditable`. Run it on
any dmg you are about to distribute:

```sh
scripts/verify-macos-release.sh hops-macos-universal.dmg
```

The workflow imports the cert into a temporary keychain
([Apple-Actions/import-codesign-certs](https://github.com/Apple-Actions/import-codesign-certs))
and decodes the `.p8` to a temp file readable only by the runner user.
`sign-macos.sh` signs in a private temp workspace, so it also works locally from
an iCloud-synced checkout (no `xattr` dance needed).

### Notes

- **No entitlements needed.** The Slint build links only Apple frameworks (no
  library-validation issue) and uses no Apple Events, so `--options runtime`
  (hardened runtime) alone satisfies notarization.
- A **bare binary can't be stapled** — only `.app`/`.dmg`/`.pkg` can — which is
  why we ship the `.app` in a `.dmg`. The CLI still works from inside:
  `hops.app/Contents/MacOS/hops daemon|tui`.

## Windows

`hops.exe` is signed with Azure Artifact Signing (formerly Trusted Signing),
which issues a short-lived certificate in the publishing organization's
validated name for each signing and keeps the key in Microsoft's HSMs. There
is no certificate file or password to store: the `sign-windows` job proves
who it is to Azure with a GitHub OIDC token.

### What is in Azure

- An **Artifact Signing account** (`hotashsigning`), in the region whose
  endpoint the workflow is given (for East US, `https://eus.codesigning.azure.net/`).
- An **identity validation** of the publishing organization, Hotash Studios,
  LLC, and a **certificate profile** of type **Public Trust** issued from it.
  Signatures chain to a root Windows trusts, and the signer's subject carries
  `O="Hotash Studios, LLC"`.
- An **app registration** with a **federated credential** for GitHub Actions:
  issuer `https://token.actions.githubusercontent.com`, subject
  `repo:<owner>/<repo>:environment:windows-signing`, audience
  `api://AzureADTokenExchange`. Only a job running in that environment of this
  repository gets a token Azure accepts.
- A role assignment of **Artifact Signing Certificate Profile Signer** to that
  app registration, scoped to the signing account. It can sign with the
  account's profiles and do nothing else in the subscription.

### In CI

`release.yml` signs in its own job, `sign-windows`, on a Windows runner. It
runs no `cargo`, checks out nothing and restores no cache: it receives only
the unsigned Windows build, which the build job uploads as
`unsigned-windows-x86_64` so that attest, which collects every `hops-*`
artifact, can never pick it up. `sign-windows` checks the zip holds exactly
`hops.exe`, `LICENSE`, `THIRD-PARTY-NOTICES.txt` and the SBOM, logs in to Azure
with [azure/login](https://github.com/Azure/login), signs `hops.exe` with
[azure/artifact-signing-action](https://github.com/Azure/artifact-signing-action)
(SHA-256, RFC-3161 timestamp from `http://timestamp.acs.microsoft.com`), and
repackages the zip. Before uploading it as `hops-windows-x86_64` it reads
`hops.exe` back out of that zip and fails unless `Get-AuthenticodeSignature`
reports `Valid`, the signer's organization is exactly `Hotash Studios, LLC`,
the signature is timestamped (the certificate itself lasts days, so an
untimestamped signature would soon stop verifying), and the binary still
carries the dependency list `cargo auditable` embedded.

Set up once, before the first release that signs:

1. Settings → Environments → `windows-signing` (create it if it is not
   there) → Deployment branches and tags → Selected branches and tags: add
   the tag rule `v*` and the branch rule `release/*`, as for `macos-signing`.
   The federated credential trusts the environment, so these rules are what
   decide which refs can sign.
2. Add the six variables below as **environment variables** of
   `windows-signing` (not secrets, and not repository variables). They are
   identifiers, not credentials.

| variable | what |
| --- | --- |
| `AZURE_CLIENT_ID` | the app registration's application (client) ID |
| `AZURE_TENANT_ID` | the directory (tenant) ID |
| `AZURE_SUBSCRIPTION_ID` | the subscription that holds the signing account |
| `ARTIFACT_SIGNING_ENDPOINT` | the account's regional endpoint, e.g. `https://eus.codesigning.azure.net/` |
| `ARTIFACT_SIGNING_ACCOUNT` | the signing account name, `hotashsigning` |
| `ARTIFACT_SIGNING_PROFILE` | the Public Trust certificate profile name |

`sign-windows` fails when any of the six is missing, naming it, on every run.
A run that cannot produce a verified signed `hops.exe` publishes nothing.

### Checking a download

In Explorer: right-click `hops.exe` → Properties → **Digital Signatures**. The
signer is Hotash Studios, LLC, and Details shows the signature is OK and has a
timestamp. Or in PowerShell:

```powershell
Get-AuthenticodeSignature .\hops.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` is `Valid`, the signer certificate's subject includes
`O="Hotash Studios, LLC"`, and `TimeStamperCertificate` is present.
