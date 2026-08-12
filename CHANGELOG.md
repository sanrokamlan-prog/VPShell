# Changelog

All notable changes to VPShell are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Pre-release versions may change local data structures before the first stable release.

## [0.1.0-alpha.8] - 2026-08-12

### Added

- Consolidated the Phase A desktop reliability work, Phase B encrypted sync protocol preview, and the isolated Android Preview source tree.
- Added restart-safe transfer recovery, bounded remote file operations, Linux monitoring, Shell Integration, migration adapters, and structured security regression coverage.
- Added the Android Preview contract and native transport boundary; Android sync, biometrics, and physical-device acceptance remain disabled or pending.

### Known limitations

- End-to-end sync coordination and user-facing synchronization are not enabled.
- SSH jump hosts, relay acceleration, and real Android device acceptance are not included in this technical preview.
- Windows installers are not Authenticode-signed; macOS artifacts are ad-hoc signed and not notarized.

## Unreleased

### Added

- Rust-owned, schema-versioned transfer recovery snapshots with atomic immutable writes, bounded size/retention, corruption fallback and explicit storage diagnostics.
- Cross-application-restart `interrupted` state with explicit retry or discard actions. Safe retries are cancellable and limited to three application-level attempts.
- Commit-boundary journaling that blocks replay after recursive commits or final package renames; recovery metadata never contains passwords, private keys, credential references, private-key paths, raw connection secrets or file contents.
- Rust-owned remote file operations for directory creation, same-directory no-overwrite rename, bounded `000..777` permission changes and explicit recursive deletion. Structured previews use connection-bound, expiring, single-use tokens and revalidate every item before mutation.
- Safe multi-selection workflows report succeeded, failed, skipped and partially applied items independently; recursive deletion never follows symlinks and is bounded to 128 roots, 64 levels and 10,000 inventoried entries.
- Added cross-directory and cross-filesystem move tasks with `fail`, collision-safe `rename`, and explicit `overwrite` policies. Moves stage in the destination directory, verify size and SHA-256, atomically commit, then clean the source; stale previews and symlink-bearing trees are skipped.
- Recursive permission edits freeze an inventory, exclude symlinks and special entries, and retain the existing 128-root, 64-level and 10,000-entry limits. File-operation batches use the persistent transfer manager for cancellation and restart decisions; recovery always creates a new preview and never replays committed work.
- File dock keyboard and focus controls now cover range selection, select all, directional/Home/End navigation, open, refresh, rename, delete, parent navigation and path focus without replacing existing transfer cancellation or recovery controls.
- Linux monitoring now uses a Rust-owned bounded session manager instead of a WebView timer. Sampling supports a validated 5-to-300-second interval, explicit pause/resume, a maximum of 16 workers, and 120 retained trend points per session.
- The host overview charts CPU, memory, disk, load and aggregate network trends. Disconnecting or switching the active session stops the old monitor, and generation checks prevent late SSH results from repopulating stopped or replaced state.
- External editing now has explicit Rust adapters for Notepad++, VS Code/Code Insiders/VSCodium and custom executables. The WebView never assembles an editor command line.
- External edit sessions use schema-versioned, atomic two-generation recovery snapshots capped at 16 records, 128 KiB and 14 days. Records contain public host identity, remote path, managed cache filename, baseline fingerprint and conflict state, but no credentials, private-key path, editor path or file contents.
- The file dock recovery and conflict center can rebind a session only to the same connected host/user, export a verified local copy without overwrite, reload the remote version, explicitly force overwrite, or discard the managed cache.
- Explicit bash/zsh Shell Integration now emits bounded token-authenticated hostname/user/cwd frames. Rust strips only valid protocol frames, preserves spoofed frames as terminal output, and maintains an eight-level self-reported nested-host stack with ancestor pop behavior.
- Compose broadcast now uses Rust-owned two-minute, single-use previews that freeze the command, connected session list and Shell context revision. Every broadcast requires confirmation, production targets are highlighted, target changes are skipped, and per-target write/skip/failure results remain distinct.
- Broadcast rejects commands likely to request passwords or interactive authentication and blocks known destructive forms such as recursive forced removal, filesystem formatting, shutdown and download-to-shell pipelines. Raw input broadcast remains unavailable.
- Added Rust SQLite schema v1 for host profiles, histories, scripts, settings and wallpaper metadata. Legacy WebView state is imported once through validated IPC, then old keys are removed; snapshots use transactional revisions, value-free event domains, 90-day/10,000-event retention and bounded corrupt-database quarantine.
- Added a strict CSP and main-window capability manifest. Custom commands are generated from one manifest and checked against the invoke handler and capability list; broad plugin defaults are no longer granted.
- Moved wallpaper and custom-font file/network handling to Rust-owned bounded atomic asset caches. PNG/JPEG/WebP and TTF/OTF/WOFF validation rejects symlinks, oversized data, URL credentials/query/fragment and redirects; WebView renders only returned managed data URLs.
- Added Rust-owned, two-stage non-sensitive migration for OpenSSH, PuTTY registry exports, Xshell, SecureCRT, MobaXterm, Tabby and Termius. Source/path changes invalidate the five-minute single-use preview, while every item and field reports ready, skipped or failed status.
- Migration scanning accepts only explicit source formats, UTF-8/UTF-16 text and ordinary files within hard path, file, total-byte, count, nesting and report limits. Symlinks are not followed; passwords, tokens, private-key material, vault data and implicit known-host trust are never imported by these adapters.
- Added the internal v1 sync cryptography layer: bounded password keyslots use Argon2id v19 and XChaCha20-Poly1305 to wrap a random VMK, while encrypted objects use HKDF-SHA256 domain keys and AAD-bound vault/object/device/sequence identities. Strict parsing, secret zeroization, tamper/domain-relocation tests and deterministic vectors are included; the coordinator and user-facing sync remain unimplemented.
- Added the internal immutable sync-provider boundary with bounded `list`/`get`/`put`, cancellation and stable diagnostics. Local Folder uses symlink-isolated paths, same-directory staging and atomic no-overwrite links; WebDAV enforces HTTPS, no redirects, explicit CA roots, conditional PUT, structured bounded XML and post-commit byte verification. The coordinator and user-facing sync remain unimplemented.
- Added an internal schema-v1 SQLite sync journal that atomically couples business callbacks, encrypted operations and outbox rows. Durable two-minute leases recover interrupted work into bounded exponential retry, cancellation pauses explicitly, six attempts are the application limit, and published work is final. Authenticated remote application persists receipts/device heads in the same transaction and rejects sequence gaps, rollback, relocated ciphertext and duplicate object identities; the background coordinator and UI remain unimplemented.
- Added the internal deterministic merge and conflict-center model for whitelisted host, history, script, setting and managed-background fields. Field registers use HLC/device/operation ordering, history is an immutable event union, tombstones preserve observed-field causality, and concurrent conflict/resolution IDs converge independently of arrival order. Versioned bounded state persists with expected revisions inside the same SQLite transaction; credentials, trust pins, local paths, private keys and sensitive history are rejected.
- Added a printable, checksummed 256-bit recovery key and an independently domain-separated recovery keyslot. Encrypted exports contain only bounded keyslots, authenticated ciphertext and a manifest, commit with no overwrite through a private atomic staging file, and perform an offline drill that authenticates and parses every event and device registry object.
- Added a bounded encrypted device registry for up to 32 public device identities. Revision checks, immutable signing-key identity, monotonic revocation, last-active-device protection and deterministic merging prevent silent reactivation; revoked publishers are rejected during recovery. Revocation does not erase a copied VMK, so suspected compromise still requires key rotation and full re-encryption. Device signatures, the coordinator and UI remain unimplemented.
- Added an internal opt-in credential vault with a separate zeroizing CVK, `credentials` password-keyslot/AAD/HKDF domains, revisioned per-device authorization and monotonic revocation. Strict typed envelopes cover SSH passwords, private-key passphrases, OpenSSH private keys and access tokens without serializing local credential references or plaintext values. The module has no Tauri command, event or logging surface; keyring restore, CVK recovery/rotation, coordinator and UI integration remain unimplemented.
- Added structured SFTP, S3-compatible and self-hosted Gateway provider adapters over backend-specific Rust transport traits. The shared immutable boundary revalidates list pages, paths, sizes and ETags, supports cancellation, requires conditional no-overwrite creation and verifies committed bytes. SFTP configuration requires a pinned SHA-256 host key; S3/Gateway require credential-free HTTPS endpoints. Gateway password/TOTP are consumed only by login and authentication errors are sanitized. Concrete SFTP sessions, S3 SigV4 and Gateway HTTP transports still require coordinator integration and real-service compatibility tests.
- Added cross-module protocol regression fixtures for v1 format rejection, AEAD tamper/domain failures, journal replay and finalized boundaries, merge arrival-order convergence and corrupt-state refusal, and provider truncation/cancellation diagnostics. The fixtures produce no network or external-service claim; real SFTP/S3/Gateway and multi-device recovery remain external acceptance work.
- Added the first Android Preview contract in Rust. A schema-versioned manifest exposes only host connection, terminal, SFTP, credential-vault and sync capabilities; broadcast, external editing, persistent monitoring and background long connections are explicitly disabled. Structured host requests validate bounded fields and opaque credential references, while the lifecycle model requires a foreground, unlocked app and clears session indexes on lock/disconnect. This is not an Android shell, native transport or APK/AAB.
- Added the Android Preview native transport boundary over the existing Rust `ssh2`/libssh2 API. It performs bounded host/user/timeout validation, verifies a pinned SHA-256 host key before authentication, accepts only zeroizing password or in-memory private-key material, and exposes a bounded SFTP directory listing that never follows symlinks or special entries. It does not spawn system `ssh`; real Android/arm64 and server compatibility remain external acceptance.
- Added a platform-isolated Android Tauri command surface for host-key inspection, pinned connection, bounded interactive terminal I/O, read-only SFTP browsing, lifecycle disconnect and Android Keystore-backed password/private-key import. The Android capability excludes desktop PTY, broadcast, editor, monitor, updater, process and dialog commands. Local aarch64 debug APK/AAB builds pass; encrypted sync coordination, biometric unlock and device testing remain incomplete.

## [0.1.0-alpha.7] - 2026-08-01

### Added

- SFTP uploads and downloads now run as backend-owned tasks with query, list, cancel and dismiss commands. Up to six tasks may run concurrently, and bounded terminal records remain available for the current application process.
- The file panel restores the matching task after it is closed, reopened or switched away from, and polls the backend as a fallback when a frontend event is missed.
- Cancellation distinguishes queued, running, cancelling, finalizing and terminal states, reports partial commits, and interrupts the active SSH socket when cooperative checkpoints alone cannot stop I/O promptly.
- Known local and remote temporary paths are cleaned after success, failure or cancellation. Remote cleanup retries once with a fresh direct connection and surfaces explicit warnings when cleanup cannot be completed.
- Added a license-aware open-source reference ledger documenting ideas studied from Tabby, Electerm, WindTerm, Termora and openFinalShell, separately from actual third-party code notices.

### Changed

- Transfer commands return an accepted task snapshot immediately instead of tying task lifetime to the mounted file panel.
- Package validation, hashing, recursive traversal, copying, extraction and atomic commit boundaries now include cancellation checkpoints. Once final commit starts, cancellation is rejected rather than pretending it succeeded.

### Known limitations

- The `v0.1.0-alpha.7` release artifact keeps transfer task records in process memory. The unreleased v0.2 worktree adds recovery decisions but is not yet a published installer.
- Pause/resume, interrupted-transfer continuation and a persistent retry queue remain roadmap work.
- A remote package command may continue briefly if the server has already detached it before the SSH socket is interrupted; cleanup reports the remaining artifact when it cannot be removed.

## [0.1.0-alpha.6] - 2026-07-31

### Fixed

- Accepting a first-use host key no longer opens three additional pre-authentication probes and then starts a fifth inspection. Confirmation now performs one required remote re-scan, verifies the `known_hosts` write locally, and starts the strict OpenSSH session directly.
- A pending host-key confirmation is bound to the original host and terminal tab. Switching tabs while the dialog is open can no longer connect a different profile with the completed confirmation.
- The host-key dialog cannot be cancelled or closed while the trust write is running, preventing an apparently cancelled operation from continuing in the background.
- Servers that accept TCP and close before sending an SSH banner/key are now reported separately from KEX incompatibility, with actionable checks for `sshd`, source-IP rules, firewall/Fail2Ban and `MaxStartups` throttling.

### Changed

- The roadmap now defines an Android client milestone that reuses the React workspace, data model and encrypted sync protocol while providing a mobile-native SSH/SFTP transport and Android Keystore credential boundary.

## [0.1.0-alpha.5] - 2026-07-30

### Fixed

- Host-key discovery now performs an isolated, no-credential system OpenSSH handshake instead of relying on `ssh-keyscan`. This avoids a Win32 OpenSSH failure where `ssh-keyscan` selects a KEX method that the installed binary does not actually support and closes before returning the server key.
- The host-key preflight, interactive terminal and Linux metrics connection now share a cached KEX allowlist derived from `ssh -Q kex`, so all OpenSSH-backed paths negotiate from the same algorithms that the current client reports as available.
- Host-key discovery uses a unique temporary `known_hosts` file, ignores user SSH config, never sends imported passwords or private keys, and removes the temporary file after parsing. The permanent trust store is still changed only after explicit fingerprint confirmation.

### Security

- Automatic compatibility does not enable SHA-1 KEX methods. Servers that only support obsolete algorithms remain blocked until a future per-host legacy mode can show an explicit security warning.

## [0.1.0-alpha.4] - 2026-07-30

### Fixed

- Interactive terminal host-key inspection now uses the system OpenSSH `ssh-keyscan`/`ssh-keygen` toolchain. A libssh2-only negotiation failure can no longer block an otherwise compatible system OpenSSH terminal.
- Saved-password connections explicitly prefer password or keyboard-interactive authentication and suppress unrelated agent identities, preventing valid imported passwords from being skipped after `MaxAuthTries` is exhausted.
- Terminal, SFTP and Linux metrics startup is staggered instead of opening three pre-auth connections at once, reducing handshake drops on small or rate-limited VPS hosts.
- SFTP handshake, host-key, network and authentication failures now remain distinct. Reading a saved password successfully is reported separately from whether a server accepts that attempt.
- Linux metrics no longer treats every error containing `publickey` as proof that a password is wrong; an empty OpenSSH exit 255 is identified as an independent sampling-connection failure.
- FinalShell migration reports passwords that could not be decrypted or stored as "not migrated" rather than claiming that the remote credential is invalid.

### Changed

- Host-key trust remains strict: unknown SHA256 fingerprints require explicit confirmation, changed keys are blocked, and trusted keys are written only to the user's guarded OpenSSH `known_hosts` file.
- SFTP handshake errors include the underlying libssh2 diagnostic and explicitly state that terminal credentials were not invalidated.

## [0.1.0-alpha.3] - 2026-07-30

### Fixed

- Re-importing an existing FinalShell host now updates its OS-keyring credential reference instead of discarding the newly migrated password. Users upgrading from alpha.2 should select the same FinalShell directory once; no passwords need to be re-entered.
- SSH connections now perform a structured host-key preflight. Unknown keys display their algorithm and SHA256 fingerprint for explicit trust, while changed keys remain hard-blocked.
- SFTP no longer aborts when the Windows libssh2 build rejects a combined host-key preference list; known algorithms are tried individually and normal verification remains mandatory.
- The Windows native title bar and colored outer frame are replaced by the VPShell title bar with working minimize, maximize/restore and close controls.

### Changed

- The terminal OpenSSH process always uses strict host-key checking after the shared preflight, so AskPass is reserved for password and private-key passphrase prompts.
- The roadmap implementation notes now record the design patterns reviewed from Tabby, Electerm and WindTerm, with clean module boundaries and no copied third-party code.

## [0.1.0-alpha.2] - 2026-07-30

### Fixed

- FinalShell passwords saved during import are now supplied to direct OpenSSH terminal sessions through a restricted AskPass helper backed by the OS keyring.
- Direct Linux host sampling reuses saved passwords or private-key passphrases and no longer opens a visible `ssh.exe` console window on Windows.
- SFTP aligns its negotiated host-key algorithm with matching OpenSSH `known_hosts` entries while continuing to reject unknown or changed keys.
- SFTP also attempts keyboard-interactive authentication for servers that route password login through PAM.
- Deleted hosts, session metadata and histories now enter a 30-day recycle bin; users can restore them or permanently remove the record and unshared OS-keyring credential.
- The legacy sample profiles and their seeded history are removed from both fresh and previously persisted workspaces.
- New and imported hosts always default to direct connections.

### Changed

- ProxyJump configuration has been removed from the Alpha UI. Per-hop automatic credentials must be designed and tested before jump-host support returns.
- Empty workspaces now show explicit add/import actions instead of a simulated terminal profile.
- First launch now opens a five-step Chinese usage guide with button-to-function mappings; the help button reopens it at any time.

### Known limitations

- SSH, Linux metrics, SFTP, packaged transfer and external editing support direct targets only.
- The OpenSSH compatibility engine still cannot report structured authentication success, so a failed attempt may enter recent history.
- Transfers do not yet support cancellation, pause/resume, persistent queues or interrupted-transfer resume.
- Sync providers and end-to-end encryption remain roadmap work.

## [0.1.0-alpha.1] - 2026-07-29

### Added

- Tauri 2 desktop shell with a React 19 operations workspace.
- xterm.js terminal connected to system OpenSSH through a Rust `portable-pty` backend.
- SSH port, identity file, ProxyJump and keepalive options.
- Host groups, environment labels, session tabs and persistent route banner.
- Basic multi-session command composer and local command history.
- Local Chinese intent search with 22 command/tool recipes, parameter forms and destructive-result filtering.
- Script center with source links, risk levels and custom recipes.
- FinalShell host/port/user import with optional password migration directly into the OS keyring.
- Ed25519 and RSA4096 OpenSSH key generation with optional passphrase encryption and public-key installation.
- Local traceroute, bounded HTTP download testing and bidirectional iperf3 UDP testing against user-controlled servers.
- Local/URL terminal wallpaper controls.
- Real SFTP directory browsing plus recursive file and directory upload/download with staged writes and verification.
- Client-side `tar + zstd` package transfer with archive path/link validation and recursive SFTP fallback when remote packaging tools are unavailable.
- Native file drag-and-drop and transfer progress in the bottom file dock.
- Linux host overview sampling for IP, CPU, memory, disk, load, traffic and top processes.
- Recent connection-attempt history ordered by most recent host.
- External editing through Notepad++, a configured editor or the platform default, with local-save detection, remote conflict blocking and explicit force overwrite.
- Signed Tauri updater artifacts and native-runner release jobs for Windows, Linux and macOS.
- Explicit WiX prerelease version mapping and a stable MSI upgrade code.
- Native macOS Apple Silicon and Intel runners instead of cross-compiling OpenSSL-dependent crates.
- Signed macOS application archives for updater delivery alongside the Intel and Apple Silicon DMG installers.
- Product architecture, encrypted sync protocol and security boundary documentation.
- Windows NSIS/MSI, Linux AppImage/DEB and macOS Intel/Apple Silicon prerelease workflow plus cross-platform compile checks.

### Known limitations

- SFTP, package transfer and external editing currently require a direct target; ProxyJump transport is rejected instead of silently bypassed.
- Transfers do not yet support cancellation, pause/resume, persistent queues or true interrupted-transfer resume.
- Remote metrics are Linux-only and use non-interactive key/agent authentication.
- External editing is limited to regular files up to 64 MiB; editor-session recovery across application restart is not implemented.
- Sync settings are stored locally; providers and end-to-end encryption are not implemented.
- Nested manual SSH sessions do not yet report host context.
- Host profiles, history and wallpapers use WebView `localStorage` and are not encrypted.
- Imported passwords and optionally saved private-key passphrases stay in the OS keyring and are not synchronized.
- Stored passwords are available to direct SFTP operations but are not injected into an OpenSSH terminal prompt.
- The system OpenSSH process does not expose structured authentication success, so a failed authentication attempt can still appear in recent connections.
- Private-key files are written only to the user-selected local path; portable encrypted export is not implemented.

[0.1.0-alpha.7]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.7
[0.1.0-alpha.6]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.1
