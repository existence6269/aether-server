# aether-server

`aether-server` is an asynchronous, in-memory WebSocket relay for Aether
ciphertext envelopes. It routes by authenticated user/device address and never
opens, decrypts, validates, or transforms encrypted message payloads. Its
device-authentication exchange verifies Aether domain-separated Ed25519
challenge proofs, but the relay never creates an Aether session or receives a
device private key. The allowlist is provisional, not an account system.

This is foundational transport code. It has not been independently audited and
is not production-ready.

## Trust boundary and architecture

- `DeviceAuthorizer` is a replaceable policy for the claimed device address
  and identity public key. After authorization, the server issues a fresh
  challenge; the client signs the protocol, server audience, address, identity
  key, challenge ID, and nonce using Aether's device-auth API. The server
  verifies the proof and consumes the challenge before connecting the device.
- The binary uses a provisional exact address/key allowlist from
  `AETHER_AUTHORIZED_DEVICES`; an empty or absent list denies all devices.
  Both connecting identities and message recipient addresses must be present
  in that allowlist. Replace this with registered account/device authorization
  when that system is designed. Device-auth proof is separate from DM
  encryption.
- `OpaqueEnvelope` contains a server message ID, sender and recipient device
  addresses, and opaque payload bytes. The server sees routing metadata and
  payload length, but treats payload contents as arbitrary bytes.
- `AppState` serializes mailbox and connection bookkeeping under an async
  mutex. Online sends are pushed to the recipient connection; offline messages
  remain in a bounded in-memory mailbox until an authenticated recipient ACK.
- Queues are process-local and are lost on restart. Delivery is at-least-once:
  an unacknowledged envelope is retried after reconnect, so clients should
  deduplicate using `message_id`.
- Authentication secrets, message payloads, ciphertext bytes, and envelope
  contents are not logged. Tracing reports only server lifecycle, connection
  lifecycle, and error codes; HTTP request/body tracing is not enabled.
- The server does not provide TLS termination. Deploy behind a trusted TLS
  endpoint and configure forwarded-header handling only in the hosting
  environment.

## WebSocket protocol

Connect to `/ws` and complete device authentication before sending relay
frames. The client first sends:

```json
{
  "type": "start",
  "device": { "user_id": "alice", "device_id": "laptop" },
  "identity_key": "<32-byte Ed25519 public key encoded as a JSON byte array>"
}
```

The server returns a `challenge` frame containing the challenge fields. The
client returns a `proof` frame with the challenge ID and 64-byte signature.
A successful exchange ends with an `authenticated` frame. The proof is valid
only for the Aether device-auth domain, configured server ID, device address,
and fresh challenge. Each connection has a 15-second authentication timeout.

After authentication, frames are UTF-8 JSON text or JSON encoded in a WebSocket
binary frame. Payload bytes are represented as a JSON byte array; serialization
does not decrypt or transform opaque bytes.

Client send:

```json
{
  "type": "send",
  "to": { "user_id": "recipient", "device_id": "phone" },
  "payload": [12, 34, 56]
}
```

The server binds `sender` from the authenticated connection, creates a UUID
`message_id`, and replies:

```json
{ "type": "accepted", "message_id": "..." }
```

The recipient receives:

```json
{
  "type": "deliver",
  "envelope": {
    "message_id": "...",
    "sender": { "user_id": "sender", "device_id": "laptop" },
    "recipient": { "user_id": "recipient", "device_id": "phone" },
    "payload": [12, 34, 56]
  }
}
```

After the client has accepted responsibility for the envelope, it acknowledges:

```json
{ "type": "ack", "message_id": "..." }
```

The relay removes the queued message only if that ID was sent to this active
recipient connection. Unknown, premature, or stale-connection acknowledgements
are rejected. Reconnecting replaces the old device connection and replays its
unacknowledged queue. Standard WebSocket Ping/Pong control frames are answered;
the application heartbeat uses `{ "type": "pong", "nonce": "..." }` in reply to
server `{ "type": "ping", "nonce": "..." }`.

Unsupported JSON, invalid device addresses, payloads over the configured bound,
and full queues receive a small typed error frame. No payload is included in an
error or log entry.

## HTTP endpoints

- `GET /healthz` is an unauthenticated liveness check.
- `GET /readyz` reports readiness and becomes `503` while graceful shutdown is
  starting.
- `GET /ws` upgrades to the authenticated WebSocket relay.

Health endpoints intentionally reveal only a fixed status string.

## Configuration

All settings are environment variables; omitted values use these defaults:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `AETHER_BIND_ADDR` | `0.0.0.0:8080` | Listener address |
| `AETHER_SERVER_ID` | `aether-server-local` | Signed device-authentication audience |
| `AETHER_AUTHORIZED_DEVICES` | unset (deny all) | Semicolon-separated `user_id/device_id=64-hex-public-key` entries |
| `AETHER_MAX_CONNECTIONS` | `10000` | Concurrent authenticated device sockets |
| `AETHER_MAX_KNOWN_DEVICES` | `100000` | Distinct devices represented by sockets or pending queues |
| `AETHER_MAX_QUEUED_MESSAGES_PER_DEVICE` | `1000` | Pending message count per recipient device |
| `AETHER_MAX_QUEUED_MESSAGES_TOTAL` | `100000` | Pending message count across all devices |
| `AETHER_MAX_QUEUED_BYTES_PER_DEVICE` | `16777216` | Pending payload bytes per recipient device |
| `AETHER_MAX_QUEUED_BYTES_TOTAL` | `536870912` | Pending payload bytes across all devices |
| `AETHER_MAX_MESSAGE_BYTES` | `1048576` | Maximum opaque payload size |
| `AETHER_MAX_WEBSOCKET_FRAME_BYTES` | `5242880` | Maximum serialized WebSocket message/frame size |
| `AETHER_OUTBOUND_CHANNEL_CAPACITY` | `64` | Per-connection buffered outbound frames |
| `AETHER_HEARTBEAT_INTERVAL_SECS` | `30` | Application Ping interval |
| `AETHER_HEARTBEAT_TIMEOUT_SECS` | `90` | Maximum wait for matching Pong |
| `RUST_LOG` | `aether_server=info,tower_http=warn` | Tracing filter |

Configuration is validated at startup. Queue bounds apply to payload storage;
message-count, device-count, and outbound-channel bounds separately constrain
metadata and connection-side buffering.

## Local development

From the repository root:

```powershell
$env:AETHER_BIND_ADDR = "127.0.0.1:8080"
cargo run -p aether-server
```

Provision development identities in the allowlist using their public identity
keys, never private seeds:

```powershell
$env:AETHER_BIND_ADDR = "127.0.0.1:8080"
$env:AETHER_AUTHORIZED_DEVICES = "alice/laptop=<64-HEX-PUBLIC-KEY>;bob/phone=<64-HEX-PUBLIC-KEY>"
cargo run -p aether-server
```

The server remains useful for checking HTTP endpoints without provisioned
devices:

```powershell
Invoke-WebRequest http://127.0.0.1:8080/healthz
Invoke-WebRequest http://127.0.0.1:8080/readyz
```

For another authorization source, implement `DeviceAuthorizer` and pass it to
`AppState::new`. Do not log proofs, keys, payload bytes, or credentials.

Run tests from the repository root:

```powershell
cargo test -p aether-server
cargo test --workspace
```

## Docker / Northflank

Configure Northflank with the repository root as the build context and
`crates/aether-server/Dockerfile` as the Dockerfile path:

```powershell
docker build -f crates/aether-server/Dockerfile -t aether-server .
docker run --rm -p 8080:8080 -e AETHER_BIND_ADDR=0.0.0.0:8080 aether-server
```

The image denies all devices unless a provisional allowlist is configured.
Configure the platform's health check at `/healthz` and readiness probe at
`/readyz`. Use TLS at the platform ingress and `wss://` clients.

## Current limitations / next phase

- Authorization is a provisional static allowlist; there is no account/device
  registration, revocation, recovery, or dynamic provisioning system.
- Device-auth proof alone does not protect transport confidentiality or
  authenticate the relay to the client; deploy TLS and use `wss://`.
- Offline storage is bounded but volatile, single-process memory. There is no
  persistence, replication, multi-node routing, or cross-region delivery.
- No rate limiting, abuse/moderation controls, durable idempotency, sender
  retries, delivery receipts beyond recipient ACK, or attachment storage.
- The application must determine device identity, TLS ingress, retry policy,
  mailbox retention, and deduplicate repeated deliveries by server message ID.
- Adding durable queues or distributed routing will require defining the
  desired delivery and transaction guarantees first.
