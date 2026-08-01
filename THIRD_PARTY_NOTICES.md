# Third-party notices

VPShell is licensed under Apache-2.0. Its Rust and npm dependencies retain their own licenses as recorded in `Cargo.lock`, `package-lock.json` and each dependency package.

## FinalShell migration compatibility

The FinalShell password compatibility routine is a clean Rust port of the publicly documented key derivation and DES decoding behavior in [`qurikuduo/finalshellPasswordDecoder`](https://github.com/qurikuduo/finalshellPasswordDecoder), licensed under Apache-2.0.

DES is supported only for importing existing FinalShell credentials. VPShell does not use DES for newly generated keys, exports or synchronized data.

Projects reviewed only for behavior or architecture are not third-party code dependencies. Their
license boundaries and the decisions derived from that review are recorded in
[`docs/OPEN_SOURCE_REFERENCES.md`](docs/OPEN_SOURCE_REFERENCES.md).
