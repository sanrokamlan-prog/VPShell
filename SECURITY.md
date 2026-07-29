# Security Policy

## Supported versions

| Version | Status |
| --- | --- |
| `0.1.0-alpha.x` | Technical preview; security fixes accepted |
| Older versions | Not supported |

The alpha release is not a production credential manager. It stores non-secret host metadata, credential references, command history, custom scripts and wallpaper settings in WebView `localStorage`. FinalShell passwords and optionally saved private-key passphrases are written directly by Rust to the operating-system keyring; plaintext is not returned to the WebView. Private-key files are written only to paths explicitly selected by the user.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not open a public issue for vulnerabilities involving:

- credential or private-key exposure;
- command injection or local code execution;
- host-key verification bypass;
- terminal escape sequence abuse;
- archive extraction or path traversal;
- synchronization encryption, rollback or conflict loss;
- update or release artifact integrity.

Include the affected version, operating system, reproducible steps, impact and a minimal proof of concept. Remove real passwords, tokens, private keys, hostnames, IP addresses and terminal history before submitting.

## Security boundaries in the alpha release

- SSH authentication and host-key verification are performed by the system OpenSSH client.
- VPShell does not automatically accept unknown or changed host keys.
- Script recipes are displayed and inserted into the command composer; they are not silently executed in the background.
- FinalShell compatibility decryption is import-only; VPShell does not export or protect new data with FinalShell's DES format.
- Stored passwords can be used by direct SFTP operations through opaque keyring references; they are not returned to the WebView or injected into OpenSSH terminal prompts.
- Network diagnostic targets are validated and executed without a shell. HTTP tests have byte/time limits; UDP tests require an existing user-operated `iperf3` server and an explicit traffic confirmation.
- SFTP and package transfer use staged paths, size/hash checks and archive path/link validation. They reject ProxyJump instead of accidentally connecting directly.
- External editing accepts only bounded regular files, writes a managed temporary copy, detects remote version conflicts and requires explicit confirmation before force overwrite.
- Transfer cancellation, interrupted-transfer resume and external-edit recovery after application restart are not implemented.
- Sync providers and end-to-end encryption are not functional in this release.
- URL wallpapers are currently loaded by the WebView. Do not use secret, authenticated or tracking-sensitive image URLs.
- Tauri Content Security Policy hardening and OS-backed local storage are planned before a stable release.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SYNC.md](docs/SYNC.md) for the target security model.
