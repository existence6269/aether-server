CREATE TABLE relay_messages (
    message_id UUID PRIMARY KEY,
    sender_user_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    payload BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    CHECK (sender_user_id <> recipient_user_id
        OR sender_device_id <> recipient_device_id),
    FOREIGN KEY (sender_user_id, sender_device_id)
        REFERENCES account_devices(user_id, device_id),
    FOREIGN KEY (recipient_user_id, recipient_device_id)
        REFERENCES account_devices(user_id, device_id)
);

CREATE INDEX relay_messages_conversation_idx
    ON relay_messages(sender_user_id, sender_device_id,
                      recipient_user_id, recipient_device_id,
                      created_at DESC, message_id DESC);

CREATE INDEX relay_messages_recipient_pending_idx
    ON relay_messages(recipient_user_id, recipient_device_id, created_at, message_id)
    WHERE delivered_at IS NULL AND deleted_at IS NULL;

CREATE TABLE relay_message_hides (
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES relay_messages(message_id) ON DELETE CASCADE,
    hidden_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, message_id)
);

CREATE TABLE relay_message_read_receipts (
    message_id UUID NOT NULL REFERENCES relay_messages(message_id) ON DELETE CASCADE,
    reader_device_id UUID NOT NULL REFERENCES account_devices(id) ON DELETE CASCADE,
    read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, reader_device_id)
);
