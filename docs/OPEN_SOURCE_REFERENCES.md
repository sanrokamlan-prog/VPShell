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

## Adopted decisions

### Transfer task model

The transfer UI must not own the only copy of task state. Long-running work is registered in the
Rust backend, exposes queryable snapshots, and uses explicit terminal states. Closing a file panel
or missing an event therefore cannot make a live task disappear.

Cancellation is a state transition, not a cosmetic button. It must distinguish cooperative
cancellation, final commit that is already too late to cancel, partially committed recursive
transfers, and temporary-resource cleanup failures.

### Session and credential boundaries

Terminal, SFTP, monitoring, sync and external editing remain separate capabilities sharing a
validated connection identity. Credentials stay behind operating-system credential references;
portable configuration and future synchronization must not serialize those local references as
usable secrets on another device.

### File operations

Remote editing uses a local working copy, explicit conflict detection and an atomic remote commit.
Directory actions must validate paths in Rust and avoid accepting shell fragments from the webview.

## Review log

- 2026-08-01: Rechecked transfer/session/file-manager patterns and license boundaries before the
  VPShell v0.2 transfer task work.
