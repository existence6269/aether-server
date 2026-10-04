CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    tag TEXT NOT NULL,
    tag_normalized TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL UNIQUE,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(tag) BETWEEN 3 AND 24),
    CHECK (length(email) BETWEEN 3 AND 320)
);

CREATE TABLE account_passkeys (
    credential_id BYTEA PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX account_passkeys_account_id_idx ON account_passkeys(account_id);

CREATE TABLE account_devices (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    identity_public_key BYTEA NOT NULL CHECK (octet_length(identity_public_key) = 32),
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, device_id)
);

CREATE INDEX account_devices_account_id_idx ON account_devices(account_id);
CREATE UNIQUE INDEX account_devices_identity_key_idx ON account_devices(account_id, identity_public_key);

CREATE TABLE email_verification_challenges (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE account_sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id UUID REFERENCES account_devices(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE browser_session_exchanges (
    code_hash BYTEA PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    callback_uri TEXT NOT NULL,
    state_hash BYTEA NOT NULL CHECK (octet_length(state_hash) = 32),
    code_challenge_hash BYTEA NOT NULL CHECK (octet_length(code_challenge_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_link_requests (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    requester_session_hash BYTEA NOT NULL REFERENCES account_sessions(token_hash) ON DELETE CASCADE,
    proposed_device_id UUID NOT NULL,
    proposed_user_id TEXT NOT NULL,
    proposed_route_device_id TEXT NOT NULL,
    proposed_identity_public_key BYTEA NOT NULL CHECK (octet_length(proposed_identity_public_key) = 32),
    display_name TEXT NOT NULL,
    approval_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(approval_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by_device UUID REFERENCES account_devices(id),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
