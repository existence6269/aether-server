ALTER TABLE account_devices
    ADD COLUMN registration_status TEXT NOT NULL DEFAULT 'active';

UPDATE account_devices
SET registration_status = 'revoked'
WHERE revoked_at IS NOT NULL;

ALTER TABLE account_devices
    ADD CONSTRAINT account_devices_registration_status_check
        CHECK (registration_status IN ('active', 'revoked')),
    ADD CONSTRAINT account_devices_registration_revocation_check
        CHECK ((registration_status = 'revoked') = (revoked_at IS NOT NULL));

CREATE INDEX account_devices_active_user_device_idx
    ON account_devices(user_id, device_id)
    WHERE registration_status = 'active' AND revoked_at IS NULL;
