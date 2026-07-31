# Changelog

All notable changes to VPShell are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Pre-release versions may change local data structures before the first stable release.

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

[0.1.0-alpha.6]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.1
