# aether-server

`aether-server` provides the Void account directory and an asynchronous
WebSocket relay for Aether ciphertext envelopes. PostgreSQL is the authoritative
account/device directory and stores opaque encrypted DM envelopes for persistent
history. The binary defaults to production
mode and refuses to start unless `DATABASE_URL` is configured and reachable.
The static device allowlist is available only when
`AETHER_ENV=development` is explicitly set; account endpoints are unavailable
in that mode without PostgreSQL.

This is foundational transport code. It has not been independently audited and
is not production-ready.

## Trust boundary and architecture

- `DeviceAuthorizer` is a replaceable policy for the claimed device address
  and identity public key. After authorization, the server issues a fresh
  challenge; the client signs the protocol, server audience, address, identity
  key, challenge ID, and nonce using Aether's device-auth API. The server
  verifies the proof and consumes the challenge before connecting the device.
- Only active, non-revoked PostgreSQL account-device records authorize relay
  connections or recipients in production. Development-only static
  authorization uses the exact address/key allowlist from
  `AETHER_AUTHORIZED_DEVICES`; an empty or absent list denies all devices.
- Account tags, optional contact emails, passkeys, and relay authorization are
  directory and access-control data only. They do **not** establish peer trust.
  Contact invitation pinning and peer trust remain client-side. Device-auth
  proof is separate from DM encryption.
- `OpaqueEnvelope` contains a server message ID, sender and recipient device
  addresses, and opaque payload bytes. The server sees routing metadata and
  payload length, but treats payload contents as arbitrary bytes.
- `AppState` serializes local connection bookkeeping under an async mutex.
  Production sends are persisted as opaque ciphertext before they are accepted.
  A PostgreSQL delivery lease assigns each pending message to one server
  instance at a time; the worker submits one message per recipient per poll,
  ordered by the durable relay sequence so a ratchet stream is not reordered.
- A recipient ACK commits `delivered_at` only after the client has durably
  saved its encrypted ratchet snapshot and local event history. Unacknowledged
  rows are reclaimed after the 30-second lease expires, and graceful disconnect
  or shutdown releases leases sooner. Delivery is at-least-once; clients
  deduplicate by message ID. Persistent clients provide a stable message ID so
  retrying an interrupted send cannot create a second relay envelope.
- Non-durable development mode retains its bounded process-local mailbox.
- PostgreSQL-backed relay instances register before serving. Authentication,
  relay ingress, and each delivery write check the instance and active device
  records in PostgreSQL. Device revocation commits an outbox event and per-
  instance delivery records in the same transaction. Each instance removes
  the local route and sender-originated queued envelopes before acknowledging
  its event; revocation returns success only after every targeted instance has
  acknowledged or has been explicitly fenced.
- The revocation linearization point is the PostgreSQL transaction that marks
  the device revoked and inserts the outbox event. Authentication consumes a
  database-backed, instance-bound one-use challenge while locking the active
  device row through local route registration. Relay ingress checks both
  endpoints under PostgreSQL row locks and a local per-device gate; delivery
  rechecks both endpoints immediately before socket write. A node acknowledges
  revocation only after its local gates drain and routes/queued envelopes are
  removed. No PostgreSQL transaction is held across socket I/O.
- No instance lease expires automatically. A crashed or unreachable instance
  therefore keeps revocation pending. Operators must first remove that node
  from load balancers/network access and ensure its process cannot serve
  traffic, then explicitly fence its recorded instance ID:

  ```sql
  UPDATE relay_instances
  SET fenced_at = now()
  WHERE instance_id = '<instance-id-from-server-log>'
    AND fenced_at IS NULL;
  ```

  The UUID is logged when the instance registers. Never run this update merely
  because a heartbeat or timeout expired. Graceful shutdown marks an instance
  fenced only after Axum has drained its WebSocket handlers. A restarted
  process receives a new instance ID and reconciles existing outbox history
  before accepting traffic. PostgreSQL availability is required for auth and
  relay; coordination failures deny new auth/sends and prevent delivery writes.
- Authentication secrets, message payloads, ciphertext bytes, and envelope
  contents are not logged. Tracing reports only server lifecycle, connection
  lifecycle, and error codes; HTTP request/body tracing is not enabled.
- Passkey ceremony state is short-lived and held server-side in process memory;
  passkey credentials, sessions, devices, and verification challenges are
  persisted in PostgreSQL. Pending ceremonies expire after five minutes.
- The server does not provide TLS termination. Deploy behind a trusted TLS
  endpoint and configure forwarded-header handling only in the hosting
  environment.

### Multi-instance revocation operations

The database schema must be migrated through
`0010_hosted_signin_handoff.sql` before deploying this version. All
instances must use the same PostgreSQL database
and a consistent schema. For the first rollout, drain and confirm shutdown of
every pre-coordination server before enabling revocation on this version;
older processes are not present in the instance registry and cannot be
invalidated by this protocol. Do not manually delete rows from `relay_instances`,
`device_revocation_outbox`, or `device_revocation_deliveries`; these records
are required to recover pending revocations after missed polling or restarts.
An instance that crashes remains an unacknowledged revocation target until an
operator has externally fenced it and sets `fenced_at`. The account revoke
request intentionally remains pending while any target is neither
acknowledged nor explicitly fenced. It can return a server error on a database
failure after revocation has committed; the durable event remains and the
request can be retried after coordination recovers.

The PostgreSQL integration tests require `TEST_DATABASE_URL` to
point to a disposable PostgreSQL database where the test role can create and
drop schemas. Without that variable these tests skip; the regular unit tests
do not substitute for database-backed migration, message persistence,
authorization, deletion, and read-receipt coverage.

The relay remains an opaque ciphertext-envelope router. PostgreSQL stores
ciphertext payload bytes, routing/order metadata, and delivery/read/delete
state; it does not read or transform payload bytes or participate in
Noise/ratchet sessions. Message edits, reactions, and reply references are
encrypted client-side and relayed as additional opaque envelopes. Deletion and
read receipts update server metadata only. History is retained until an
operator removes it from PostgreSQL; configure database backups and capacity
accordingly. Migrations are applied automatically at startup by the configured
database role. For deployment, back up the database, grant the service role
the migration DDL rights it needs, then start the updated server against the
existing database with `DATABASE_URL`; startup applies any pending migrations
before serving. Verify `/readyz` and inspect migration logs before routing
traffic. `DATABASE_URL` must point at the service database; use a separate
disposable database with `TEST_DATABASE_URL` for tests, never the production
database.

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
  signin pages.

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
Email verification remains implemented for account email changes, but it is
not part of signup or sign-in. The signup page reports account creation only.
Expired or invalid email-change links show an accessible explanation without
echoing the token. The hosted page's
WebAuthn RP origin is the configured
`AETHER_WEBAUTHN_ORIGIN`, which must be the hosted account portal's HTTPS origin
and must not be the desktop React/Tauri origin.

1. `POST /api/accounts/signup` with `{"tag":"alice","email":"alice@example.org"}`
   creates an immutable random UUID account ID, reserves the case-insensitive
   unique tag/email, and returns a short-lived WebAuthn registration ceremony
   ID and browser creation options. Signup starts are limited to 30 per
   database-wide minute window across all instances.
   Tags are 3–24 ASCII letters, digits, or underscores; common service,
   administrative, and Void-reserved names are rejected case-insensitively.
2. Complete `navigator.credentials.create()` in the system browser and POST
   `{"ceremony_id":"…","credential":{…}}` to
   `/api/accounts/signup/finish`. The server verifies and persists the passkey.
   An account cannot sign in or appear in the public directory until its
   passkey registration has completed. Email is contact information, not an
   authentication factor; the account is owned by the passkey.
3. For Tauri system-browser sign-in, generate separate 32-byte
   cryptographically random values for `state` and `code_verifier`; encode
   both as unpadded base64url (43 characters). Compute
   `code_challenge = BASE64URL_NOPAD(SHA256(decoded code_verifier bytes))`.
   Keep the verifier only in native memory. Open the hosted
   `/account/signin?tag=<tag>#state=<state>&code_challenge=<code_challenge>`
   page on the configured WebAuthn origin. The state and challenge are in the
   URL fragment, which is not sent to the server, and the page removes the
   fragment from its address bar as soon as it reads them. The page performs the passkey
   assertion and returns the browser to the same host at `/account/complete`.
   No code, verifier, or bearer session token is placed in that URL.

   The equivalent JSON ceremony contract is `POST /api/accounts/signin` with
   `{"tag":"alice","state":"<43-char-base64url-state>","code_challenge":"<43-char-base64url-SHA256-verifier>"}`.
   The response is `{"ceremony_id":"<uuid>","options":{"publicKey":{...}}}`.
   Pass `options.publicKey` to `navigator.credentials.get()`, then POST
   `{"ceremony_id":"<uuid>","credential":{...browser assertion JSON...}}` to
   `/api/accounts/signin/finish`. It returns the fixed hosted completion URL,
   `{"redirect_uri":"https://<configured-origin>/account/complete"}`.
   The native app polls `/api/accounts/session/poll` with
   `{"state":"<state>","code_verifier":"<original verifier>"}`. A `204 No
   Content` response means the browser ceremony is still pending; a successful
   JSON response contains the session token and is consumed exactly once.
   The server verifies the state and PKCE challenge atomically; pending
   exchanges expire after five minutes. The browser never receives the
   verifier or bearer token. This polling request requires HTTPS and the
   client must use the standard bearer authorization header for subsequent
   authenticated account API calls.

   The server continues to accept the previous optional loopback callback
   format for older clients. Deploy the updated account server and apply its
   migrations before distributing a client that uses hosted completion and
   polling; an older server does not expose `/api/accounts/session/poll`.

   For other system-browser clients, implement the same form, WebAuthn API
   credential conversions, and callback behavior using the documented JSON
   contract; never place the bearer token in a callback URL.
   `POST /api/accounts/logout` revokes the current session;
   `GET /api/accounts/me` returns only the current account summary:
   `{"account_id":"<uuid>","tag":"alice","email_verified":false,"email_change_pending":false}`.
   `PATCH /api/accounts/me` requires the same bearer authorization and accepts
   one or both editable fields, for example
   `{"tag":"new_tag","email":"new@example.org"}`. Omitted fields are unchanged;
   an empty patch and unknown fields are rejected. Tags use the signup
   validation rules and are changed immediately, with a global
   case-insensitive uniqueness check. A tag edit changes neither immutable
   `account_id` nor any device IDs or DeviceAddress aliases.

   Email edits reserve a globally case-insensitive unique pending address and
   send its verification link through Resend when email delivery is configured.
   Until that link is verified, the current email remains active; the pending
   address is not used for sign-in recovery or exposed by the API. The response remains the public
   account summary, with `email_change_pending: true` indicating a pending
   change and no address or token. Successful verification atomically promotes
   the pending email and clears the pending state; invalid, expired, or
   superseded links do not change the active email. Submitting the active
   email again cancels any pending change. Email delivery failure does not
   replace the active email and the failed pending request is cleared.
4. `GET /api/directory/{tag}` returns only the account UUID and public tag for
   accounts with a completed passkey registration.
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

The device API contracts are:

| Method and path | Authentication | Success response |
| --- | --- | --- |
| `POST /api/devices/first-enrollment/challenge` | Authenticated unbound account session | `{"challenge_id":"<uuid>","challenge":{...}}` |
| `POST /api/devices/first-enrollment/finish` | Same account session and device signature | `{"device":{"id":"<uuid>","user_id":"...","device_id":"...","display_name":"...","created_at":"...","current":true}}` |
| `POST /api/devices/session/challenge` | Authenticated account session | `{"challenge_id":"<uuid>","challenge":{...}}` |
| `POST /api/devices/session/finish` | Same account session and device signature | `204 No Content` |
| `POST /api/devices/link` | Authenticated unbound session | `{"request_id":"<uuid>","approval_token":"<64 hex chars>","expires_in_seconds":3600}` |
| `GET /api/devices/link` | Authenticated active-device session | Array of pending request objects (`request_id`, `user_id`, `device_id`, `display_name`, `created_at`) |
| `POST /api/devices/link/{request_id}/approve` | Authenticated active-device session | `204 No Content` |
| `POST /api/devices/link/{request_id}/complete` | The requesting unbound session | A `DeviceEntry` object |
| `GET /api/devices` | Authenticated account session | Array of active `DeviceEntry` objects |
| `DELETE /api/devices/{device_id}` | Account session belonging to the account | `204 No Content` after cross-instance revocation delivery completes |

For additional-device linking, the start body is
`{"device":{"user_id":"...","device_id":"..."},"identity_public_key":[32 bytes],"display_name":"..."}`.
The complete body is `{"approval_token":"<token returned by start>"}`.
The approval token is bound server-side to the exact account, route aliases,
device key, requester session and request ID; approval is performed by a
separately authenticated existing device. The link flow does not allow a
public key alone to enroll a device.

`account_devices.registration_status` is database-backed and constrained to
`active` or `revoked`. Newly accepted first-device and approved link records
are active; revocation changes both the status and `revoked_at` in the same
transaction. Only active records are returned or accepted for relay auth.

Email verification tokens, session bearer tokens, browser exchange codes, and
browser state and PKCE challenge values are stored only as SHA-256 hashes in
the database; the PKCE verifier is never sent to or stored by the server. The
legacy callback listener must bind only to loopback and stop listening after
its single callback; the current native client uses hosted completion and
polling instead. No account session cookies are issued. Passkey proofs and
private keys are never logged or returned. Resend failures do not return
provider details. API transport must be protected by TLS; ensure ingress access
logs redact the email-verification query token and legacy sign-in query state.
Current sign-in state and challenge are sent in the browser URL fragment, not
in the HTTP request. Passkey ceremonies are process-local, so
an in-flight browser ceremony cannot be completed after a process restart or
on a different server instance.

## Configuration

All settings are environment variables; omitted values use these defaults:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `AETHER_ENV` | `production` | `production` requires PostgreSQL; only explicit `development` permits static device authorization |
| `AETHER_BIND_ADDR` | `0.0.0.0:8080` | Listener address |
| `AETHER_SERVER_ID` | `aether-server-local` | Signed device-authentication audience |
| `AETHER_AUTHORIZED_DEVICES` | unset (deny all) | Development-only semicolon-separated `user_id/device_id=64-hex-public-key` entries |
| `DATABASE_URL` | required in production | PostgreSQL URL; stores accounts/devices/sessions and authorizes the production relay |
| `AETHER_WEBAUTHN_RP_ID` | required with database | WebAuthn relying-party ID (host name) |
| `AETHER_WEBAUTHN_ORIGIN` | required with database | Exact HTTPS hosted portal origin permitted for passkeys and account API CORS; must not be the desktop React origin |
| `AETHER_PUBLIC_URL` | optional | HTTPS origin used for email-change verification; configure together with both Resend settings and match `AETHER_WEBAUTHN_ORIGIN` |
| `RESEND_API_KEY` | optional | Resend secret for email-change confirmation; configure only on the server together with the other email-delivery settings |
| `RESEND_FROM_EMAIL` | optional | Verified sender address for email-change confirmation; configure with the other email-delivery settings |
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
$env:AETHER_ENV = "development"
$env:AETHER_BIND_ADDR = "127.0.0.1:8080"
cargo run -p aether-server
```

Provision development identities in the allowlist using their public identity
keys, never private seeds:

```powershell
$env:AETHER_BIND_ADDR = "127.0.0.1:8080"
$env:AETHER_ENV = "development"
$env:AETHER_AUTHORIZED_DEVICES = "alice/laptop=<64-HEX-PUBLIC-KEY>;bob/phone=<64-HEX-PUBLIC-KEY>"
cargo run -p aether-server
```

For accounts, configure PostgreSQL and WebAuthn values. Migrations run
automatically at startup. Email changes require all three optional email
delivery settings; signup and sign-in do not. Never configure Resend credentials
in the frontend or commit them:

```powershell
$env:DATABASE_URL = "<PostgreSQL connection URL>"
$env:AETHER_WEBAUTHN_RP_ID = "void.example.org"
$env:AETHER_WEBAUTHN_ORIGIN = "https://void.example.org"
# Optional: required only for email-change confirmation
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
`TEST_DATABASE_URL` to an isolated disposable PostgreSQL database to execute
the migration, account/device enrollment, encrypted DM history/persistence,
authorization/deletion/read-receipt, and two-instance revocation integration
tests. These tests create and drop per-test schemas.

## Docker / Northflank

Configure Northflank with the repository root as the build context and
`crates/aether-server/Dockerfile` as the Dockerfile path:

```powershell
docker build -f crates/aether-server/Dockerfile -t aether-server .
docker run --rm -p 8080:8080 -e AETHER_BIND_ADDR=0.0.0.0:8080 `
  -e AETHER_ENV=production -e DATABASE_URL `
  -e AETHER_WEBAUTHN_RP_ID -e AETHER_WEBAUTHN_ORIGIN aether-server
```

Set the listed environment variables in the hosting platform before starting
the container. Production startup fails if `DATABASE_URL` is absent or
unreachable, and it never consults `AETHER_AUTHORIZED_DEVICES`. The server
automatically applies pending migrations using its PostgreSQL role; grant that
role the schema/table/index privileges required for migrations. If email-change
confirmation is needed, configure all three optional email-delivery settings
server-side.
Configure the platform's health check at `/healthz` and readiness probe at
`/readyz`. Use TLS at the platform ingress and `wss://` clients.

## Current limitations / next phase

- The static allowlist is available only in explicitly selected development
  mode (`AETHER_ENV=development`) when PostgreSQL is absent.
- Account recovery, account deletion, passkey replacement, and distributed
  passkey ceremony storage are not implemented. Signup starts are limited by
  one database-wide rate counter (30 per minute), not per source IP.
- Device-auth proof alone does not protect transport confidentiality or
  authenticate the relay to the client; deploy TLS and use `wss://`.
- PostgreSQL provides durable ciphertext envelopes and cross-instance relay
  delivery, but there is no cross-region replication or automatic retention.
  Configure backups, capacity limits, and an operator-managed retention
  policy; history remains stored until explicitly deleted or the database
  retention policy removes it.
- Delivery is at-least-once. Clients must retain their encrypted local ratchet
  snapshot and deduplicate messages by stable message ID. A fresh device does
  not gain the keys needed to decrypt historical envelopes; there is no secure
  history-transfer protocol.
- Typing status is relayed across instances from short-lived PostgreSQL state
  (five-second expiry); it remains best-effort, and clients clear it on timeout
  or connection loss. Abuse controls, attachment storage, and cross-region
  delivery are not implemented.
