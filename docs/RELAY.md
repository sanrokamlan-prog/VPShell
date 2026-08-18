# VPShell Relay reference service

`vpshell-relay` is a small self-hosted TCP relay for VPShell desktop clients. It is a
reference deployment component, not a hosted service and not an SSH server.

## Trust boundary

The relay authenticates a client with a 32-byte pre-shared token, checks an operator-owned
target allowlist, opens one outbound TCP connection, and copies bytes in both directions. It
never receives an SSH password/private key, never terminates SSH, never validates the target
host key, and never parses SSH or terminal bytes. The VPShell client performs the final SSH
handshake and host-key verification after the relay reports readiness.

Protocol v1 uses a server random 256-bit challenge, a client random nonce, the target authority,
and an 8-byte token key id in an HMAC-SHA256 request proof. The server response is a second
HMAC-SHA256 proof over the status, session id, nonces, and request digest. A captured request is
therefore bound to one challenge and cannot be replayed on another connection. The control
handshake is authenticated but not encrypted: a network observer can see the configured target
authority and packet timing. The SSH payload remains end-to-end encrypted by the final SSH
connection. Use an administrator-controlled network ACL or an audited outer TLS/VPN layer when
metadata confidentiality is required; the reference service does not claim to provide that
layer.

## Protocol v1 wire format

Every integer is unsigned big-endian. `magic` is ASCII `VPSR`; `version` is `1`. There is no
generic unbounded frame decoder.

```text
server hello: magic[4] | version[2] | serverNonce[32]
client auth:  magic[4] | version[2] | clientNonce[32] | keyId[8] |
              targetLength[2] | targetHost[targetLength] | targetPort[2] | proof[32]
server reply: magic[4] | version[2] | status[1] | sessionId[16] | proof[32]
```

`targetLength` is `1..=253`; the complete request is at most 335 bytes. `keyId` is the first eight
bytes of `SHA256(token)` and supports bounded key selection without sending the token. The client
proof is:

```text
HMAC-SHA256(token, "vpshell-relay-v1-client" || serverNonce || client-auth-without-proof)
```

The server proof is:

```text
HMAC-SHA256(token, "vpshell-relay-v1-server" || serverNonce || clientNonce ||
            status || sessionId || SHA256(client-auth-without-proof))
```

Status `0` means ready; `1` authentication failed; `2` target denied; `3` target unavailable; and
`4` audit unavailable. Unknown magic, versions, statuses, lengths, encodings, hosts, or ports fail
closed. Capacity and pre-authentication source-rate rejection close the connection without an
unsigned explanatory frame. A client must verify the server proof before treating any status as
authentic or sending SSH bytes.

## Build and run

The binary is desktop-only and is compiled by the normal locked Rust CI matrix. It has no Tauri
command or capability and cannot be launched by the WebView.

```text
cargo run --locked --manifest-path src-tauri/Cargo.toml --bin vpshell-relay -- token --output /etc/vpshell-relay/token
cargo run --locked --manifest-path src-tauri/Cargo.toml --bin vpshell-relay -- serve \
  --listen 0.0.0.0:7443 \
  --token-file /etc/vpshell-relay/token \
  --allow-target ssh.example.net:22 \
  --audit-file /var/log/vpshell-relay.jsonl
```

The token generator uses create-only file creation and Unix mode `0600`; it never prints the
token. The server rejects missing, symlinked, non-regular, oversized, or group/world-readable
token files. The audit file has the same symlink and permission checks. `--allow-target` is
repeatable and must contain at least one exact `host:port` or `[ipv6]:port`; there is no wildcard,
CIDR, arbitrary DNS, or user-supplied target mode.

For a local client-side loopback entry point:

```text
cargo run --locked --manifest-path src-tauri/Cargo.toml --bin vpshell-relay -- connect \
  --relay relay.example.net:7443 \
  --listen 127.0.0.1:0 \
  --target ssh.example.net:22 \
  --token-file /home/user/.config/vpshell/relay-token
```

The connect mode accepts only loopback clients and is bounded to 32 local connections. Its
printed local address is an operational hint, not a credential. A future VPShell UI route may
use the same Rust client function; no token is stored in WebView state or sent through IPC.

## Hard limits and audit

The server defaults to 128 total sessions, 8 active sessions per source IP, 30 authentication
attempts per source IP per minute, a 1 GiB aggregate session byte limit, a 120-second idle limit,
a four-hour session limit, and ten-second handshake/target-connect limits. Every value has a
validated upper bound; there is no unlimited mode. Source buckets are capped and expired.

JSONL audit records contain schema version, phase, random request id, salted short hashes of the
source and allowlisted target, a stable outcome code, byte count, and duration. They do not
contain token material, key ids, raw addresses, hostnames, credentials, SSH bytes, or underlying
socket errors. If the audit sink fails, new sessions fail closed.

The implementation and tests cover challenge/replay/tamper resistance, exact target policy,
authentication and concurrency limits, byte/idle/duration bounds, token/audit file permissions,
opaque SSH-like bytes, and audit redaction. Multi-region deployment, firewall policy, log
rotation, outer TLS/VPN, long-duration packet loss, and real SSH server compatibility remain
external deployment acceptance work.
