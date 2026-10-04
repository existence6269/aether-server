# aether-server

`aether-server` provides the Void account directory and an asynchronous,
in-memory WebSocket relay for Aether ciphertext envelopes. PostgreSQL is the
authoritative account/device directory when `DATABASE_URL` is configured.
Without it, the explicit local device allowlist remains available for relay
development and the account API returns `503`.

This is foundational transport code. It has not been independently audited and
is not production-ready.

## Trust boundary and architecture

- `DeviceAuthorizer` is a replaceable policy for the claimed device address
  and identity public key. After authorization, the server issues a fresh
  challenge; the client signs the protocol, server audience, address, identity
  key, challenge ID, and nonce using Aether's device-auth API. The server
  verifies the proof and consumes the challenge before connecting the device.
- With PostgreSQL configured, only active account-device records authorize
  relay connections or recipients. Otherwise the binary uses the exact
  address/key allowlist from `AETHER_AUTHORIZED_DEVICES`; an empty or absent
  list denies all devices.
- Accounts, verified tags/emails, passkeys, and relay authorization are
  directory and access-control data only. They do **not** establish peer trust.
  Contact invitation pinning and peer trust remain client-side. Device-auth
  proof is separate from DM encryption.
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
- Passkey ceremony state is short-lived and held server-side in process memory;
  passkey credentials, sessions, devices, and verification challenges are
  persisted in PostgreSQL. Pending ceremonies expire after five minutes.
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
- `GET /account/signup` and `/account/signin` serve same-origin system-browser
  passkey pages when the PostgreSQL account directory is configured.
- `GET /account` is the hosted account portal linking the hosted signup and
  signin pages and reporting successful email verification.

Health endpoints intentionally reveal only a fixed status string.

## Account API

All account routes require PostgreSQL configuration. JSON request objects reject
unknown fields. Account and passkey endpoints neither accept nor store DM
plaintext, Aether ratchet/session secrets, or device private keys.

The server hosts a minimal same-origin account portal at `GET /account` and
hosted signup/signin forms at `/account/signup` and `/account/signin`. The forms
use the browser WebAuthn API against the configured API origin. Passkey
credential objects live only in page memory; pages do not persist them, create
API sessions, use server-managed session cookies, or store bearer tokens.
Email verification returns to the portal with a success notice; expired or
invalid verification links show an accessible explanation without echoing the
token. Signup instructs users to verify email and return to the desktop app to
sign in. The hosted page's WebAuthn RP origin is the configured
`AETHER_WEBAUTHN_ORIGIN`, which must be the hosted account portal's HTTPS origin
and must not be the desktop React/Tauri origin.

1. `POST /api/accounts/signup` with `{"tag":"alice","email":"alice@example.org"}`
   creates an immutable random UUID account ID, reserves the case-insensitive
   unique tag/email, emails a verification link through Resend, and returns a
   short-lived WebAuthn registration ceremony ID and browser creation options.
   Tags are 3–24 ASCII letters, digits, or underscores; common service,
   administrative, and Void-reserved names are rejected case-insensitively.
2. Complete `navigator.credentials.create()` in the system browser and POST
   `{"ceremony_id":"…","credential":{…}}` to
   `/api/accounts/signup/finish`. The server verifies and persists the passkey.
   The emailed GET link verifies the email at `/api/accounts/email/verify`;
   clients may also POST `{"token":"…"}` to that endpoint.
3. For Tauri system-browser sign-in, first have the native client listen on an
   available loopback port at an exact path, e.g.
   `http://127.0.0.1:49152/void/callback`. Generate separate 32-byte
   cryptographically random values for `state` and `code_verifier`; encode
   both as unpadded base64url (43 characters). Compute
   `code_challenge = BASE64URL_NOPAD(SHA256( decoded code_verifier bytes ))`.
   Keep the verifier only in native memory. Open
   `/account?callback_uri=<percent-encoded-loopback-URL>&state=<state>&code_challenge=<code_challenge>`
   in the system browser. The portal links to sign-in while preserving those
   parameters. The hosted page asks for the account tag, performs the passkey
   assertion, and redirects only to the supplied loopback URI with `code` and
   the unchanged `state` query parameters; it never receives the verifier.
   The bearer token is never returned to the browser page or included in its
   redirect.

   The equivalent JSON ceremony contract is
   `POST /api/accounts/signin` with
   `{"tag":"alice","callback_uri":"http://127.0.0.1:49152/void/callback","state":"<43-char-base64url-state>","code_challenge":"<43-char-base64url-SHA256-verifier>"}`.
   The response is `{"ceremony_id":"<uuid>","options":{"publicKey":{...}}}`.
   Pass `options.publicKey` to `navigator.credentials.get()`, then POST
   `{"ceremony_id":"<uuid>","credential":{...browser assertion JSON...}}` to
   `/api/accounts/signin/finish`. That returns only
   `{"redirect_uri":"http://127.0.0.1:49152/void/callback?code=<opaque>&state=<state>"}`.
   The hosted page navigates to `redirect_uri`.

   The native listener must check the returned state exactly against the
   original random state, extract code/state, then POST
   `{"code":"<opaque code>","state":"<state>","code_verifier":"<original 43-char verifier>","callback_uri":"<same callback URI>"}`
   to `/api/accounts/session/exchange` using a native HTTP client. The server
   verifies the PKCE-style SHA-256 verifier challenge and atomically consumes
   the code/state/callback tuple. Only that one-time exchange returns
   `{"account_id":"<uuid>","tag":"alice","session_token":"<bearer>","expires_at":<unix seconds>}`.
   Codes expire after five minutes and are consumed atomically; a replay,
   verifier, callback, or state mismatch fails. The callback must use plain HTTP with an
   explicit nonzero port and a literal loopback IP (`127.0.0.0/8` or `::1`),
   with no userinfo, query, or fragment in the registered callback URL.
   Hostnames (including `localhost`), non-loopback IPs, HTTPS URLs, and
   implicit/default ports are rejected. Native clients must use their
   32-byte random state to prevent login CSRF and bind the response to the
   initiating app request. Authenticated HTTP calls use the standard bearer
   authorization header with the exchanged session token.

   For other system-browser clients, implement the same form, WebAuthn API
   credential conversions, and callback behavior using the documented JSON
   contract; never place the bearer token in a callback URL.
   `POST /api/accounts/logout` revokes the current session;
   `GET /api/accounts/me` returns only the current account summary:
   `{"account_id":"<uuid>","tag":"alice","email_verified":true,"email_change_pending":false}`.
   `PATCH /api/accounts/me` requires the same bearer authorization and accepts
   one or both editable fields, for example
   `{"tag":"new_tag","email":"new@example.org"}`. Omitted fields are unchanged;
   an empty patch and unknown fields are rejected. Tags use the signup
   validation rules and are changed immediately, with a global
   case-insensitive uniqueness check. A tag edit changes neither immutable
   `account_id` nor any device IDs or DeviceAddress aliases.

   Email edits reserve a globally case-insensitive unique pending address and
   send its verification link through Resend. Until that link is verified, the
   currently verified email remains active; the pending address is not used
   for sign-in recovery or exposed by the API. The response remains the public
   account summary, with `email_change_pending: true` indicating a pending
   change and no address or token. Successful verification atomically promotes
   the pending email and clears the pending state; invalid, expired, or
   superseded links do not change the active email. Submitting the active
   email again cancels any pending change. Email delivery failure does not
   replace the active email and the failed pending request is cleared.
4. `GET /api/directory/{tag}` returns only the account UUID and public tag.
   It never returns email addresses, devices, or identity keys. Directory
   lookup does not pin contacts or establish trust.
5. The just-exchanged passkey session is initially unbound. If
   `GET /api/devices` returns an empty list, the native app must enroll its
   first device before connecting to the relay:
   `POST /api/devices/first-enrollment/challenge` with
   `{"device":{"user_id":"<existing legacy alias>","device_id":"<existing legacy alias>"},"identity_public_key":[32 bytes],"display_name":"..."}`.
   The response contains `challenge_id` and the fresh Aether `challenge`,
   audience-bound to the configured `AETHER_SERVER_ID`.
   Sign that challenge with the proposed local identity private key and POST
   `{"challenge_id":"<uuid>","proof":{"signature":[64 bytes]}}` to
   `/api/devices/first-enrollment/finish`. Success returns
   `{"device":{"id":"<uuid>","user_id":"...","device_id":"...","display_name":"...","created_at":"...","current":true}}`.
   The account session is bound to that device only after signature
   verification. Enrollment is one-use and transactional: PostgreSQL locks
   the account row and admits the insert only while there are still zero
   active devices. The first-device proof is device authentication, not peer
   trust.

   `GET /api/devices` lists the caller's active devices without public keys.
   `DELETE /api/devices/{device_uuid}` revokes a device and its sessions.
   A logged-in client binds its API session to an already registered device
   using `POST /api/devices/session/challenge` and
   `POST /api/devices/session/finish`; the latter requires a valid signature
   from that device's registered Aether identity key.
6. A session already bound to an active device may request another with
   `POST /api/devices/link`,
   providing its existing `user_id`/`device_id` alias, public identity key,
   and display name. A request is not relay-authorized until an already
   registered, cryptographically bound device approves it using
   `GET /api/devices/link` and
   `POST /api/devices/link/{request_uuid}/approve`. The requesting session
   then claims it with `POST /api/devices/link/{request_uuid}/complete`, sending
   the one-time `approval_token` returned when it started the request.
   Existing DeviceAddress aliases are stored and routed unchanged. Registered
   Aether identity public keys are globally unique across all accounts and
   remain reserved even after device revocation. Reusing a key for another
   account (or registering it a second time) is rejected as
   `400 invalid_request`; a concurrent duplicate that passes the initial check is
   still rejected by PostgreSQL's unique constraint. The migration refuses to
   proceed if legacy account rows already assign one key to multiple accounts;
   operators must resolve ownership before applying it. Route aliases are not
   changed by this constraint.

Email verification tokens, session bearer tokens, browser exchange codes, and
browser state and PKCE challenge values are stored only as SHA-256 hashes in
the database; the PKCE verifier is never sent to or stored by the server. The
callback listener must bind only to loopback and should stop listening after
receiving its single callback. No account session cookies are issued. Passkey
proofs and private keys are never logged or returned. Resend failures do not
return provider details. API
transport must be protected by TLS; ensure ingress access logs redact the
email-verification query token and sign-in query state. Passkey ceremonies are
process-local, so
an in-flight browser ceremony cannot be completed after a process restart or
on a different server instance.

## Configuration

All settings are environment variables; omitted values use these defaults:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `AETHER_BIND_ADDR` | `0.0.0.0:8080` | Listener address |
| `AETHER_SERVER_ID` | `aether-server-local` | Signed device-authentication audience |
| `AETHER_AUTHORIZED_DEVICES` | unset (deny all) | Semicolon-separated `user_id/device_id=64-hex-public-key` entries |
| `DATABASE_URL` | unset | PostgreSQL URL; enables account API and database-backed relay directory |
| `AETHER_WEBAUTHN_RP_ID` | required with database | WebAuthn relying-party ID (host name) |
| `AETHER_WEBAUTHN_ORIGIN` | required with database | Exact HTTPS hosted portal origin permitted for passkeys and account API CORS; must not be the desktop React origin |
| `AETHER_PUBLIC_URL` | required with database | HTTPS origin used for the hosted portal and email verification links; must match `AETHER_WEBAUTHN_ORIGIN` |
| `RESEND_API_KEY` | required with database | Resend secret; configure only in the server environment |
| `RESEND_FROM_EMAIL` | required with database | Verified sender address configured in Resend |
| `AETHER_DATABASE_MAX_CONNECTIONS` | `20` | PostgreSQL connection pool limit |
| `AETHER_DATABASE_CONNECT_TIMEOUT_SECS` | `10` | PostgreSQL pool acquire/connect timeout |
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

For accounts, configure PostgreSQL and the server-side email/WebAuthn values.
Migrations run automatically at startup. Do not configure Resend credentials in
the frontend or commit them:

```powershell
$env:DATABASE_URL = "<PostgreSQL connection URL>"
$env:AETHER_WEBAUTHN_RP_ID = "void.example.org"
$env:AETHER_WEBAUTHN_ORIGIN = "https://void.example.org"
$env:AETHER_PUBLIC_URL = "https://void.example.org"
$env:RESEND_API_KEY = "<server secret>"
$env:RESEND_FROM_EMAIL = "accounts@void.example.org"
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

Pure account-validation and relay tests need no production secrets. Set
`TEST_DATABASE_URL` to an isolated disposable PostgreSQL database to also run
the account migration smoke test.

## Docker / Northflank

Configure Northflank with the repository root as the build context and
`crates/aether-server/Dockerfile` as the Dockerfile path:

```powershell
docker build -f crates/aether-server/Dockerfile -t aether-server .
docker run --rm -p 8080:8080 -e AETHER_BIND_ADDR=0.0.0.0:8080 aether-server
```

Without `DATABASE_URL`, the image denies all devices unless a provisional
allowlist is configured. For account mode, configure all database, WebAuthn,
public URL, and Resend variables in the platform's server-side environment.
Configure the platform's health check at `/healthz` and readiness probe at
`/readyz`. Use TLS at the platform ingress and `wss://` clients.

## Current limitations / next phase

- The static allowlist remains a local fallback only when PostgreSQL is absent.
- Account recovery, account deletion, passkey replacement, distributed passkey
  ceremony storage, and account API rate limiting are not implemented.
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
