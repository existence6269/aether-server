CREATE TABLE relay_instances (
    instance_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fenced_at TIMESTAMPTZ
);

CREATE TABLE device_revocation_outbox (
    id UUID PRIMARY KEY,
    device_record_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX device_revocation_outbox_device_idx
    ON device_revocation_outbox(device_record_id, created_at DESC);

CREATE TABLE device_revocation_deliveries (
    event_id UUID NOT NULL REFERENCES device_revocation_outbox(id) ON DELETE CASCADE,
    instance_id UUID NOT NULL REFERENCES relay_instances(instance_id),
    acknowledged_at TIMESTAMPTZ,
    PRIMARY KEY (event_id, instance_id)
);

CREATE INDEX device_revocation_deliveries_pending_idx
    ON device_revocation_deliveries(instance_id, event_id)
    WHERE acknowledged_at IS NULL;

CREATE TABLE relay_auth_challenges (
    challenge_id UUID PRIMARY KEY,
    instance_id UUID NOT NULL REFERENCES relay_instances(instance_id),
    device_record_id UUID NOT NULL REFERENCES account_devices(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX relay_auth_challenges_expiry_idx
    ON relay_auth_challenges(expires_at);
