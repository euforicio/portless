# PKI and macOS service

This slice keeps routine proxy management separate from installation privilege.
The daemon runs as `root:wheel`, binds only `127.0.0.1` and `::1` on ports 80
and 443, and exposes a `0660` Unix socket to one explicitly selected management
group. The packages never invoke `sudo`; the ordinary-user `init` command owns
the single fixed `/usr/bin/sudo` reconciliation boundary.

## PKI lifecycle

`internal/pki.Open` creates an ECDSA P-256 root with `crypto/x509` and stores it
under a caller-selected absolute state directory:

| Artifact | Mode | Purpose |
| --- | ---: | --- |
| `root.pem` | `0600` | Active root certificate and private key |
| `ca.pem` | `0644` | Public active root used for trust operations |
| `leaf/<exact-host>.pem` | `0600` | Atomic leaf certificate and private key bundle |

The directory and leaf directory are `0700` and must be owned by the daemon's
effective UID. Existing symlinks, unexpected file types, unsafe modes, invalid
keys, and expired roots fail closed. SNI has no default certificate. Hostnames
must be exact ASCII DNS names under `.localhost`; an `AllowHost` callback ties
issuance to the current registered-route snapshot.

Leaves are cached in memory and on disk, are bounded by the active root's
expiry, and renew once they enter the configured renewal window.

The opt-in LAN authority uses the same exact-host implementation with `.local`
as its allowed suffix and a hard 256-leaf disk/memory bound. Eviction is
deterministic by file modification time and hostname, unsafe cache entries fail
closed, and issuance is permitted only for the current exact LAN registration.
It never issues wildcard certificates. This user-owned CA is not automatically
trusted by other devices; LAN HTTPS output identifies the public certificate
that the user must explicitly install on each intended client.

Root rotation is deliberately two phase because trust is external:

1. `PrepareRootRotation` writes an inactive root and returns its exact SHA-256
   fingerprint and public certificate path.
2. Add that candidate with `ApplyTrust(TrustInstall, candidatePath)` during an
   explicit privileged operation.
3. `ActivateRoot(fingerprint)` atomically promotes only that candidate,
   invalidates old-issuer leaves, and retains the previous public root.
4. Remove the previous exact certificate with
   `ApplyTrust(TrustRemove, previousPath)`.
5. Call `FinalizeRootRotation` after removal succeeds.

`SystemTrusted` is read-only and compares exact certificate DER exported from
the system keychain. Trust changes use `/usr/bin/security` with the admin domain
and `/Library/Keychains/System.keychain`; they never select a certificate by
common name or suppress arbitrary command failures.

## LaunchDaemon and installation

`internal/service.DefaultConfig(group)` resolves the selected group and
describes the production layout:

| Artifact | Ownership/mode |
| --- | --- |
| `/usr/local/libexec/portless` | `root:wheel 0755` |
| `/Library/LaunchDaemons/com.euforicio.portless.plist` | `root:wheel 0644` |
| `/Library/Application Support/Portless` | `root:wheel 0700` |
| `/var/run/portless` | `root:<management-group> 0750` |
| `/var/run/portless/management.sock` | `root:<management-group> 0660` |
| `/Library/Logs/Portless` | `root:wheel 0750` |

The caller must resolve and pass an existing narrow management group. `admin`
is the safe macOS default; deployments that need non-admin operators should use
a dedicated group rather than broadening the socket to `staff`.

The generated property list uses absolute arguments, explicit root ownership,
loopback-only listeners, `KeepAlive`, `ProcessType=Interactive`, and an octal
`0077` umask. `KeepAlive` already implies initial launch, so `RunAtLoad` is not
duplicated. Production packaging must validate the result with:

```sh
/usr/bin/plutil -lint -- /Library/LaunchDaemons/com.euforicio.portless.plist
```

When explicitly configured, the property list passes one absolute Apple
`container` executable to the daemon. When absent, the adapter flag is omitted
and the daemon has no container-runtime requirement. This avoids inherited `PATH` selection and the client-only
`PORTLESS_CONTAINER_CLI` environment override. The root daemon never executes
that user-managed path with root credentials: it launches trusted
`/bin/launchctl asuser`, drops to the registration's daemon-derived login UID
and groups, and executes the CLI inside that user's Apple-container domain.

`Installer.Install` and `Installer.Upgrade` atomically reconcile binary and
plist content, ownership, and modes. Identical input returns an unchanged audit
report. `Status` reports paths, ownership, modes, sizes, and SHA-256 digests.
`Uninstall` removes only the exact binary, plist, and socket and retains state,
certificates, and logs for recovery. Destructive state removal is a separate
`PurgeData` call.

Launchd mutation remains explicit through `Config.Commands`:

- Install/upgrade after changed artifacts: conditionally `bootout` an already
  loaded job, then `bootstrap`, `enable`, and `kickstart`.
- Status: `launchctl print system/<label>`; use only its exit status, never parse
  its human-oriented output as a stable schema.
- Uninstall: conditionally `bootout` before removing artifacts.

The installer invokes these plans only at the install, upgrade, or uninstall
privilege boundary. Routine route operations connect directly to the Unix
socket without `sudo`.

The executable wires these pieces into an ordinary-user `init` sequence:
artifacts first, local authority creation, exact CA trust installation, fixed
launchctl application when artifacts changed or the job is absent, and a
bounded management-socket readiness check, followed by doctor from the original
user process. It also publishes the non-secret CA certificate at
`/usr/local/share/portless/ca.pem` for child compatibility metadata. The sequence is idempotent and
recoverable by retry; it does not roll back pre-existing trust or state.

## Unix management boundary

`ListenManagement` refuses relative or overlong paths, symlinks, regular files,
unowned stale sockets, and active sockets. It binds while the parent directory
is owner-only, applies ownership and `0660`, then opens directory traversal to
the selected group with `0750`.

Every accepted connection must pass `Credentials`. On Darwin this reads the
kernel's `LOCAL_PEERCRED` through `golang.org/x/sys/unix`; authorization uses
the kernel UID and groups, never an owner field supplied in a request. Protocol
handling must additionally impose deadlines, bounded request sizes, and the
narrow route-management schema described in the architecture.

The implementation limits management concurrency, authenticates before reading
request data, requires exactly one bounded newline-delimited JSON frame, rejects
unknown fields and trailing frames, and applies a total read/operation/write
deadline. Shutdown closes accepted management connections before waiting for
handler goroutines.

Ordinary automated tests use temporary files, real P-256 certificates and TLS
handshakes, real child executables and Unix sockets, native `plutil`, read-only
`launchctl` and system-keychain inspection, and read-only live `/etc/hosts`
plans. They do not load a system daemon, bind privileged ports, change a live
trust store, or write `/etc/hosts`.

The manual `Privileged macOS integration` workflow covers the provisioned
lifecycle that is unsafe on developer machines and ordinary CI. It requires the
protected `privileged-macos-integration` environment plus the exact dispatch
confirmation `RUN-PRIVILEGED-PORTLESS`, runs only on a fresh GitHub-hosted
macOS runner, rejects pre-existing Portless artifacts, and exercises real
`init`, idempotent install/upgrade, launchd, system CA trust, HTTPS routing on
ports 80/443, and uninstall. Its cleanup trap removes only the fixed Portless
service and retained state paths. Final assertions verify that the job,
artifacts, socket, public CA, and exact trusted certificate are absent after
first observing uninstall's retained-state contract.
