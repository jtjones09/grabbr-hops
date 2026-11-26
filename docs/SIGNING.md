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
which issues a certificate in the publishing organization's validated name,
valid for 72 hours, and keeps the key in Microsoft's HSMs. There is no
certificate file or password to store: the `sign-windows` job proves who it
is to Azure with a GitHub OIDC token.

### What is in Azure

- An **Artifact Signing account**, in the region whose endpoint the workflow
  is given (`https://<region>.codesigning.azure.net/`).
- An **identity validation** of the publishing organization, Hotash Studios,
  LLC, and a **certificate profile** of type **Public Trust** issued from it.
  Signatures chain to a root Windows trusts; the signer's subject carries
  `O="Hotash Studios, LLC"` and its certificate the Artifact Signing Public
  Trust EKU `1.3.6.1.4.1.311.97.1.0`.
- An **app registration** with one **federated credential**, bound to the
  `windows-signing` environment of this repository by its immutable subject.
- The **Artifact Signing Certificate Profile Signer** role for that app
  registration, scoped to the one certificate profile.

### In CI

`release.yml` signs in its own job, `sign-windows`, on a Windows runner. It
runs no `cargo`, checks out nothing and restores no cache: it receives only
the unsigned Windows build, which the build job uploads as
`unsigned-windows-x86_64`. The attest job downloads each release artifact by
name, so it never collects that one. `sign-windows` checks the zip holds
exactly `hops.exe`, `LICENSE`, `THIRD-PARTY-NOTICES.txt` and the SBOM, logs
in to Azure with [azure/login](https://github.com/Azure/login), signs
`hops.exe` with
[azure/artifact-signing-action](https://github.com/Azure/artifact-signing-action)
(SHA-256, RFC-3161 timestamp from `http://timestamp.acs.microsoft.com`), and
repackages the zip. Before uploading it as `hops-windows-x86_64` it reads
`hops.exe` back out of that zip and fails unless `Get-AuthenticodeSignature`
reports `Valid`, the signer's organization is exactly `Hotash Studios, LLC`,
the certificate carries the code-signing and Artifact Signing Public Trust
EKUs, the signature is timestamped (without one it stops verifying when the
certificate expires), and the binary still carries the dependency list
`cargo auditable` embedded.

### Setting it up

Do these in order. A workflow that names an environment which does not
exist creates it, with no protection, so the environment and its rules come
before anything can sign through it.

1. **The environment.** Settings → Environments → New environment →
   `windows-signing`. Under Deployment branches and tags choose Selected
   branches and tags and add the tag rule `v*` and the branch rule
   `release/*`, as for `macos-signing`.

   Recommended: also turn on **Required reviewers** and add the maintainer.
   Anyone with write access can push a `release/*` branch carrying a
   modified `release.yml`, and that run would be admitted to the
   environment and could sign what it likes. A required review puts a
   person in front of every signing run, at one click per release; a
   reviewer may approve their own run unless "Prevent self-review" is on.

2. **The variables.** In the same environment, under Environment variables,
   add the six below. They must be environment variables, never repository
   variables: `vars.*` resolves a repository variable for a run on any
   branch. They are identifiers, not credentials, so they are not secrets.

   | variable | what |
   | --- | --- |
   | `AZURE_CLIENT_ID` | the app registration's application (client) ID |
   | `AZURE_TENANT_ID` | the directory (tenant) ID |
   | `AZURE_SUBSCRIPTION_ID` | the subscription that holds the signing account |
   | `ARTIFACT_SIGNING_ENDPOINT` | the account's regional endpoint, `https://<region>.codesigning.azure.net/` |
   | `ARTIFACT_SIGNING_ACCOUNT` | the signing account name |
   | `ARTIFACT_SIGNING_PROFILE` | the Public Trust certificate profile name |

   `sign-windows` fails, naming each one missing, on every run.

3. **Immutable OIDC subjects.** By default a repository created before
   2026-07-15 gets name-based OIDC subjects
   (`repo:<owner>/<repo>:environment:windows-signing`). A credential that
   trusts a name trusts whichever repository holds that name later, after a
   rename, transfer or deletion. Opt the repository into the immutable form,
   which adds the owner's and repository's numeric IDs, through the
   repository's OIDC settings or the API:

   ```sh
   gh api -X PUT repos/<owner>/<repo>/actions/oidc/customization/sub \
     -F use_default=true -F use_immutable_subject=true
   gh api repos/<owner>/<repo>/actions/oidc/customization/sub --jq .sub_claim_prefix
   ```

   The second command prints the prefix tokens now carry,
   `repo:<owner>@<owner_id>/<repo>@<repo_id>`. The two IDs are also what

   ```sh
   gh api repos/<owner>/<repo> --jq '.owner.id, .id'
   ```

   prints, owner first.

4. **The federated credential.** On the app registration, add a federated
   credential whose subject is the immutable one, for this environment
   alone:

   ```json
   {
     "name": "hops-windows-signing",
     "issuer": "https://token.actions.githubusercontent.com",
     "subject": "repo:<owner>@<owner_id>/<repo>@<repo_id>:environment:windows-signing",
     "audiences": ["api://AzureADTokenExchange"]
   }
   ```

   ```sh
   az ad app federated-credential create --id <application-object-id> --parameters credential.json
   ```

   Remove any name-based credential for the same environment, so no
   credential trusts a name.

5. **The role.** Assign Artifact Signing Certificate Profile Signer to the
   app registration's service principal at the scope of the one certificate
   profile. The portal's Access control (IAM) assigns at the account; the
   profile scope is set with the Azure CLI:

   ```sh
   az role assignment create \
     --assignee <service-principal-object-id> \
     --role "Artifact Signing Certificate Profile Signer" \
     --scope "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CodeSigning/codeSigningAccounts/<account>/certificateProfiles/<profile>"
   ```

To get a signed zip without releasing, run the workflow by hand from a
`release/*` branch or a `v*` tag; it is attached to the run as the
`hops-windows-x86_64` artifact.

### What the signing job trusts

`sign-windows` can sign as the publisher, so whatever runs in it can too.
Besides the runner image and the two pinned actions, that is code fetched
while it runs:

- The signing action, at the pinned commit, installs the PowerShell module
  `ArtifactSigning` 0.1.8 from the PowerShell Gallery. The version is pinned;
  the content is not checked against a hash.
- That module fetches NuGet packages at run time: the action's cache steps
  name `Microsoft.Windows.SDK.BuildTools` 10.0.26100.4188,
  `Microsoft.ArtifactSigning.Client` 1.0.128 and `sign`
  0.9.1-beta.26227.3. These too are pinned by version only.
- `cache-dependencies` is set to `"false"`, and this is load-bearing. The
  action's cache keys are its dependency versions alone, and a cache entry
  can be written by any run with the job's runtime token, including the
  runs on `main` that compile third-party build scripts. With the cache on,
  a module planted under that key would be restored into the signing job.
  `tests/release_pipeline.rs` fails if the input changes.

The job's OIDC token stays readable to the module while it signs. Clearing
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` in the
signing step was considered and not done: whether a step's `env:` overrides
the variables the runner sets for OIDC is unverified, and the Azure CLI
session from the login step already lets the module sign, so clearing them
would not take that away.

### Checking a download

In Explorer: right-click `hops.exe` → Properties → **Digital Signatures**. The
signer is Hotash Studios, LLC, and Details shows the signature is OK and has a
timestamp. Or in PowerShell:

```powershell
Get-AuthenticodeSignature .\hops.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` is `Valid`, the signer certificate's subject includes
`O="Hotash Studios, LLC"`, and `TimeStamperCertificate` is present.
