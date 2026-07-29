# Changelog

All notable changes to VPShell are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Pre-release versions may change local data structures before the first stable release.

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
- Client-side `tar + zstd` package transfer with archive path/link validation and recursive SFTP fallback.
- Native file drag-and-drop and transfer progress in the bottom file dock.
- Linux host overview sampling for IP, CPU, memory, disk, load, traffic and top processes.
- Successful-connection history ordered by most recent host.
- External editing through Notepad++, a configured editor or the platform default, with local-save detection, remote conflict blocking and explicit force overwrite.
- Signed Tauri updater artifacts and native-runner release jobs for Windows, Linux and macOS.
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
- Private-key files are written only to the user-selected local path; portable encrypted export is not implemented.

[0.1.0-alpha.1]: https://github.com/sanrokamlan-prog/vpshell/releases/tag/v0.1.0-alpha.1
