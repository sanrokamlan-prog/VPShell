# VPShell Relay reference service

`vpshell-relay` is a small self-hosted TCP relay for VPShell desktop clients. It is a
reference deployment component, not a hosted service and not an SSH server.

## Trust boundary

The relay authenticates a client with one of at most four active 32-byte pre-shared tokens, checks an operator-owned
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
token files. `serve` accepts `--token-file` one to four times so old and new tokens can overlap
during a bounded rotation; an empty, duplicate, or larger token set fails before bind. The audit
file has the same symlink and permission checks. `--allow-target` is
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

## Hardened Linux deployment

The repository includes a systemd baseline, non-secret environment example, and logrotate policy
under `deploy/relay/`. They are examples for a dedicated Linux host, not an installer. Review the
unit against the target distribution before enabling it. Build a release binary from a reviewed
commit with `--locked`, record its checksum, and install it outside a user-writable directory.

```text
install -o root -g root -m 0755 target/release/vpshell-relay /usr/local/libexec/vpshell-relay
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpshell-relay
install -d -o root -g vpshell-relay -m 0750 /etc/vpshell-relay
install -d -o vpshell-relay -g vpshell-relay -m 0700 /var/log/vpshell-relay
/usr/local/libexec/vpshell-relay token --output /etc/vpshell-relay/token-current
chown vpshell-relay:vpshell-relay /etc/vpshell-relay/token-current
chmod 0600 /etc/vpshell-relay/token-current
install -o root -g root -m 0644 deploy/relay/vpshell-relay.service /etc/systemd/system/vpshell-relay.service
install -o root -g root -m 0644 deploy/relay/relay.env.example /etc/vpshell-relay/relay.env
install -o root -g root -m 0644 deploy/relay/vpshell-relay.logrotate /etc/logrotate.d/vpshell-relay
systemd-analyze verify /etc/systemd/system/vpshell-relay.service
systemctl daemon-reload
systemctl enable --now vpshell-relay.service
```

Edit `relay.env` before starting. It contains only the listen address, one exact target, and file
paths; never place token contents in it. Add targets by replacing `ExecStart` in a reviewed
systemd drop-in with repeated `--allow-target` arguments. Restrict ingress to known client or VPN
networks and egress to the exact SSH targets. The reference protocol does not provide metadata
confidentiality, public certificate authentication, service discovery, or automatic firewall
changes.

The unit removes capabilities, restricts writable paths to the audit directory, and permits only
IPv4/IPv6 sockets. The logrotate policy renames the private audit file and restarts the process so
the append-only writer opens the replacement; it deliberately does not use `copytruncate`. A
restart terminates active relay sessions, which is preferable to an unrecorded audit interval.

## Token rotation and revocation

Protocol v1 sends only an eight-byte hash-derived key id. The server uses it to select one of at
most four loaded tokens and then verifies the complete HMAC proof. Key ids and token values are
never written to audit records.

1. Generate `token-next` with the create-only `token` command and deliver it through an approved
   secret channel. Never print it in a shell trace, issue, Actions log, or PR.
2. Restart the server with both files by repeating `--token-file` for `token-current` and
   `token-next`. Test both client populations against an allowlisted non-production SSH target and
   verify the final SSH host key at the client.
3. Move every managed client to `token-next`. Audit intentionally cannot identify which token was
   used, so completion requires the operator's inventory and explicit client canaries.
4. Restart with only `token-next`. New requests using the old token fail before target connect.
   Deleting a file without restarting does not revoke its in-memory token.
5. Securely remove the old token after rollback is no longer allowed. For suspected compromise,
   skip overlap, restart immediately with a new token, and treat every active session as closed.

`RelayTokenSet` rejects zero tokens, more than four tokens, and duplicate key ids. There is no
remote token-management API, WebView IPC, hot reload, or silent fallback token. Side-by-side
listeners are required when an operator needs a rotation without terminating active sessions.

## Protocol upgrade and rollback

The listener speaks exactly protocol v1. There is no version negotiation or downgrade: another
version produces a stable local error or a close before authentication. Audit schema version 1 is
independent from the wire version.

For a future wire version, run the reviewed candidate on a separate listener and port with
separate synthetic token and audit files. Exercise authentication, target denial, final SSH
host-key verification, byte/idle/duration limits, and audit failure before moving clients. Keep the
previous binary and v1 configuration unchanged during the canary. Cut over explicit client
configuration; do not make one listener guess a version from malformed bytes. Rollback restores
the previous verified binary, configuration, and token set, then starts fresh challenges. It never
translates or replays captured control frames.

## Failure-recovery drill

Run this drill on an isolated non-production node after every binary, unit, firewall, or outer
TLS/VPN change. Record only timestamps, stable outcome codes, counts, and artifact checksums.

1. Connect through the loopback client to a synthetic target and verify its SSH host key. Confirm
   raw addresses, token material, credentials, and SSH bytes do not appear in JSONL.
2. Try a wrong token, a removed token after restart, an unlisted target, and a protocol-version
   mismatch. None may open the target connection or fall back to another version or token.
3. Make the audit path unwritable or full. New authenticated sessions must fail before payload
   relay. Repair storage and restart; an instance whose audit sink failed stays fail closed in
   memory and does not silently recover.
4. Remove or weaken the token file and restart. Startup must fail before bind. Restore a private,
   regular non-symlink file from the approved secret store or issue a new token.
5. Stop the service during an active synthetic session. It must close. Start the previous verified
   binary/configuration and confirm a fresh challenge, session id, SSH handshake, and audit record;
   no old request or session is resumed.
6. Exercise byte, idle, duration, global, per-IP, and authentication-rate limits. Recovery must not
   widen the target allowlist or firewall.
7. Rotate the audit file with the committed policy. Verify mode `0600`, restart completion, JSONL
   parseability, and retention; archive only to an access-controlled location.

Real firewall rules, account creation, TLS/VPN, DNS, disk-full behavior, log collection,
multi-region failover, packet loss, and long-duration sessions remain environment-specific
external acceptance. Rust loopback tests and this runbook do not prove a production deployment.

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
authentication and concurrency limits, byte/idle/duration bounds, token overlap/revocation,
unsupported-version rejection, token/audit file permissions, opaque SSH-like bytes, and audit
redaction. Multi-region deployment, firewall policy, execution of log rotation, outer TLS/VPN,
long-duration packet loss, and real SSH server compatibility remain external acceptance work.
