# Third-party notices

VPShell is licensed under Apache-2.0. Its Rust and npm dependencies retain their own licenses as recorded in `Cargo.lock`, `package-lock.json` and each dependency package.

## FinalShell migration compatibility

The FinalShell password compatibility routine is a clean Rust port of the publicly documented key derivation and DES decoding behavior in [`qurikuduo/finalshellPasswordDecoder`](https://github.com/qurikuduo/finalshellPasswordDecoder), licensed under Apache-2.0.

DES is supported only for importing existing FinalShell credentials. VPShell does not use DES for newly generated keys, exports or synchronized data.

## rusqlite and bundled SQLite

VPShell uses `rusqlite` 0.40.2 with default features disabled and only its `bundled` feature for the local Rust-owned event store.
`rusqlite` is distributed under MIT or Apache-2.0; its `libsqlite3-sys` dependency and bundled
SQLite amalgamation retain their upstream license notices. The dependency is used without network,
extension loading or SQLCipher features. It can be removed after exporting the schema-v1 state
snapshot and replacing the local event store implementation.

## RustCrypto sync cryptography

VPShell uses `argon2` 0.5.3, `chacha20poly1305` 0.10.1 and `hkdf` 0.12.4 from RustCrypto, plus
`getrandom` 0.3.4 from the rust-random project. These crates are distributed under MIT or
Apache-2.0. Argon2's pure-Rust `blake2` and `password-hash` dependencies retain the same upstream
dual-license boundary. Default features are disabled and only the alloc/zeroize features recorded
in `docs/DEVELOPMENT.md` are enabled. No third-party source was copied into VPShell; the crates are
used through their public APIs and remain independently replaceable through the versioned v1
format and fixed compatibility vectors.

## Sync provider parsing

VPShell directly uses `quick-xml` 0.41.0 and `percent-encoding` 2.3.2, both distributed under the
MIT license, for bounded WebDAV multistatus parsing and validated href decoding. Both packages
were already present as transitive dependencies of the locked Tauri/reqwest graph; their default
features remain disabled. No third-party WebDAV implementation or source code was copied.

## Android SSH compatibility transport

VPShell uses `ssh2` 0.9.6 and its `libssh2-sys` dependency through their public Rust APIs. Both are
distributed under MIT or Apache-2.0. The `vendored-openssl` feature is enabled only for Android so the existing
libssh2 transport can be cross-compiled for Android instead of linking a host OpenSSL installation;
the bundled OpenSSL source retains the Apache-2.0 license and upstream notices. This adds native C
build work but no network, telemetry, shell-process or Tauri permission at runtime. The compatibility
transport is isolated behind `android_native_transport.rs` and can be removed after an audited
pure-Rust engine passes the same host-key, authentication and SFTP tests.

## Android credential store

VPShell uses `android-native-keyring-store` 1.0.0 and `keyring-core` 1.0.0 through their public
Rust APIs on Android. Both are distributed under MIT or Apache-2.0. The store encrypts credential
values using Android Keystore-backed keys and stores only ciphertext in its named
SharedPreferences vault. It adds JNI/Android context access but no Android permission, network,
telemetry or backup surface. The dependency can be removed when VPShell owns an equivalent audited
Keystore adapter behind the same opaque-reference boundary; credential values must be deleted or
migrated explicitly before such removal.

## Android biometric access gate

VPShell uses `tauri-plugin-biometric` 2.3.2 through its public Rust API. The plugin is distributed
under MIT or Apache-2.0 and uses Apache-2.0 AndroidX Biometric transitively on Android. It adds no
Android runtime permission and receives no SSH credential material; Rust calls it only to gate the
Android lifecycle before local credential-backed operations are authorized. The plugin currently
allows Android `BIOMETRIC_WEAK` and an optional device-credential fallback, so VPShell does not
claim a strong-biometric guarantee. It can be removed together with the optional access gate
without changing stored SSH credential formats. No plugin or AndroidX source or asset was copied
into VPShell.

Projects reviewed only for behavior or architecture are not third-party code dependencies. Their
license boundaries and the decisions derived from that review are recorded in
[`docs/OPEN_SOURCE_REFERENCES.md`](docs/OPEN_SOURCE_REFERENCES.md).
