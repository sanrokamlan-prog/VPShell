# Contributing to VPShell

VPShell is Windows-first but keeps its terminal, data and synchronization contracts cross-platform. Contributions should preserve that boundary and must not weaken host-key, credential, script or archive safety for convenience.

## Development setup

1. Install Node.js 22+, Rust stable and the [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/).
2. Run `npm install`.
3. Run `npm run build`.
4. Run `cargo check --manifest-path src-tauri/Cargo.toml` from a shell with the platform toolchain loaded.

On Windows, `scripts/windows-dev.ps1` locates Visual Studio Build Tools and loads its developer environment.

## Pull requests

- Keep changes scoped and explain user-visible behavior.
- Add or update tests in proportion to the risk.
- Do not add a new cloud dependency when a provider interface is sufficient.
- Do not bypass OpenSSH host-key prompts or auto-accept changed keys.
- Treat terminal output, remote paths, archives, URLs and synchronized objects as untrusted input.
- Mark roadmap-only UI and documentation clearly; do not claim placeholders are implemented.
- Do not include credentials, real production hosts, terminal history or private incident logs.

Before submitting:

```bash
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo check --manifest-path src-tauri/Cargo.toml
```

## Commit style

Use a short imperative subject, for example:

```text
Add shell integration event parser
Harden archive path validation
Document WebDAV conflict behavior
```

## License

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
