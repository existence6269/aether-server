CREATE TABLE relay_typing_states (
    sender_user_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    is_typing BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        sender_user_id, sender_device_id,
        recipient_user_id, recipient_device_id
    ),
    CHECK (sender_user_id <> recipient_user_id
        OR sender_device_id <> recipient_device_id),
    FOREIGN KEY (sender_user_id, sender_device_id)
        REFERENCES account_devices(user_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_user_id, recipient_device_id)
        REFERENCES account_devices(user_id, device_id) ON DELETE CASCADE
);

CREATE INDEX relay_typing_states_recipient_expiry_idx
    ON relay_typing_states(recipient_user_id, recipient_device_id, expires_at);

CREATE INDEX relay_typing_states_expiry_idx
    ON relay_typing_states(expires_at);
