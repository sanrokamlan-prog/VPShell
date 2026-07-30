# Changelog

All notable changes to VPShell are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Pre-release versions may change local data structures before the first stable release.

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

[0.1.0-alpha.3]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.1
