# Open-source engineering references

VPShell is independently implemented in Rust, Tauri and React. This document records mature
projects reviewed during product and architecture work. A reference does not mean that its source
code was copied into VPShell.

Actual third-party code used or adapted by VPShell is listed separately in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## Reference policy

- MIT, BSD and Apache-2.0 projects may be adapted only after a file-level license and attribution
  review.
- GPL and AGPL projects are behavior and architecture references only unless VPShell deliberately
  adopts compatible licensing for the affected component.
- Partially open or source-available projects are behavior references only for code that is not
  clearly published under a compatible license.
- Every imported or substantially adapted implementation must be added to
  `THIRD_PARTY_NOTICES.md` in the same change.

## Reviewed projects

| Project | License boundary | What VPShell studies | Code reuse status |
| --- | --- | --- | --- |
| [Tabby](https://github.com/Eugeny/tabby) | MIT | Global transfer visibility, tab/session restoration, logical key names, vault separation, plugins and synchronized input | Architecture and interaction reference; no copied code |
| [Electerm](https://github.com/electerm/electerm) | MIT | Independent terminal/SFTP/sync modules, remote-file editing, quick commands, broadcast input and multiple sync backends | Architecture and interaction reference; no copied code |
| [WindTerm](https://github.com/kingToolbox/WindTerm) | Apache-2.0 for released source; repository is only partially open | Authentication-first session startup, integrated local/remote filer, transfer performance and session restoration | Behavior reference unless a specific released source file is separately reviewed |
| [Termora](https://github.com/TermoraDev/termora) | AGPL-3.0 | Bounded concurrent transfers, server-to-server transfer workflow, visual chmod, safe remote editing and hierarchical hosts | Behavior reference only; no copied code |
| [openFinalShell](https://github.com/kexue-aihao/openfinalshell) | No repository-level license detected on 2026-08-01 | FinalShell migration behavior and familiar desktop layout | Behavior reference only; no copied code; never treated as a credential-decoding authority |
| [FinalShell password decoder](https://github.com/qurikuduo/finalshellPasswordDecoder) | Apache-2.0 | Legacy FinalShell DES import compatibility | Clean Rust port; see `THIRD_PARTY_NOTICES.md` |
| [rusqlite](https://github.com/rusqlite/rusqlite) | MIT or Apache-2.0 | Local schema-v1 SQLite transaction/event store | Dependency used with `bundled`, no copied source; version/feature and removal plan recorded in `THIRD_PARTY_NOTICES.md` |
| [RustCrypto password-hashes/AEADs/KDFs](https://github.com/RustCrypto) | MIT or Apache-2.0 | Argon2id key wrapping, XChaCha20-Poly1305 envelopes and HKDF domain separation | Stable crates used through public APIs; no copied source; exact versions/features and replacement plan recorded in `THIRD_PARTY_NOTICES.md` and development docs |
| [quick-xml](https://github.com/tafia/quick-xml) and [percent-encoding](https://github.com/servo/rust-url) | MIT | Bounded WebDAV XML parsing and href decoding | Existing locked packages promoted to direct dependencies; public APIs only, no copied source or provider implementation |
| [ssh2-rs](https://github.com/alexcrichton/ssh2-rs), libssh2 and OpenSSL | MIT or Apache-2.0 / BSD-style / Apache-2.0 | Android-compatible SSH/SFTP transport without a system executable | Existing dependency used through public APIs; vendored OpenSSL only enables NDK cross-compilation; no copied source |
| [android-native-keyring-store](https://github.com/open-source-cooperative/android-native-keyring-store) and keyring-core | MIT or Apache-2.0 | Android Keystore-backed opaque credential references | Dependencies used through public APIs; no copied source; platform scope and removal plan recorded in `THIRD_PARTY_NOTICES.md` |
| [Tauri Biometric plugin](https://github.com/tauri-apps/plugins-workspace/tree/db9c5998feff9384f9cbbefcbe0d45937c00a1fc/plugins/biometric) and AndroidX Biometric | MIT or Apache-2.0 / Apache-2.0 | Rust-owned system biometric/device-credential prompt and capability checks | Plugin 2.3.2 used through its public Rust API; AndroidX is transitive; no source copied; access-gate and removal boundaries recorded in `THIRD_PARTY_NOTICES.md` |
| [MaidKit](https://github.com/Solsynth/MaidKit/tree/eaf4922072960158f04021ed866323e6c17209cd) | AGPL-3.0 | SSH-only non-intrusive management, dual-pane SFTP, services/containers/databases, jump/forwarding, audit, scripts and explicit agent action approval | Behavior and product decomposition reference only; no source, assets, text or implementation copied/adapted into Apache-2.0 VPShell |

## Adopted decisions

### Transfer task model

The transfer UI must not own the only copy of task state. Long-running work is registered in the
Rust backend, exposes queryable snapshots, and uses explicit terminal states. Closing a file panel
or missing an event therefore cannot make a live task disappear.

Cancellation is a state transition, not a cosmetic button. It must distinguish cooperative
cancellation, final commit that is already too late to cancel, partially committed recursive
transfers, and temporary-resource cleanup failures.

The v0.2 recovery tranche adds a Rust-owned, schema-versioned snapshot store rather than copying
frontend state. Snapshots are immutable atomic files with bounded retention; restart converts
active work to an explicit interrupted decision. Only requests that have not crossed a commit
boundary can be retried, and retry attempts are capped at three. This behavior was independently
implemented from the reviewed projects; no third-party transfer or persistence code was copied.

### Session and credential boundaries

Terminal, SFTP, monitoring, sync and external editing remain separate capabilities sharing a
validated connection identity. Credentials stay behind operating-system credential references;
portable configuration and future synchronization must not serialize those local references as
usable secrets on another device.

### File operations

Remote editing uses a local working copy, explicit conflict detection and an atomic remote commit.
Directory actions must validate paths in Rust and avoid accepting shell fragments from the webview.
The v0.2 file-operation tranche implements this independently with structured SFTP calls, expiring
single-use preview tokens, no-overwrite rename, non-following symlink rules, bounded recursive
inventory and per-item partial results. No reviewed project's file-manager code was copied.

## Review log

- 2026-08-01: Rechecked transfer/session/file-manager patterns and license boundaries before the
  VPShell v0.2 transfer task work.
- 2026-08-09: Recorded the independent cross-restart recovery, bounded retry and commit-boundary
  decisions; no new third-party code or dependency was added.
- 2026-08-09: Rechecked remote file-operation and visual chmod behavior before the independent
  preview-token/batch implementation; no new third-party code or dependency was added.
- 2026-08-10: Enabled the existing ssh2/libssh2 vendored OpenSSL build path for Android NDK
  cross-compilation and recorded its dependency boundary; no upstream implementation was copied.
- 2026-08-10: Added the maintained Android-native keyring store through its public Rust API and
  recorded its Keystore/SharedPreferences, license and removal boundaries; no upstream source was copied.
- 2026-08-17: Reviewed Tauri plugins-workspace biometric implementation at commit
  `db9c5998feff9384f9cbbefcbe0d45937c00a1fc` and AndroidX documentation; used plugin 2.3.2's
  public Rust API and recorded its weak-biometric/device-credential contract without copying source.
- 2026-08-17: Reviewed MaidKit README at commit
  `eaf4922072960158f04021ed866323e6c17209cd`; its AGPL-3.0 code/assets remain outside VPShell,
  and only the abstract SSH-only module split, dual-pane operations, audit and approval patterns
  were recorded for later independent design.
