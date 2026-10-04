DO $migration$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM account_devices
        GROUP BY identity_public_key
        HAVING count(DISTINCT account_id) > 1
    ) THEN
        RAISE EXCEPTION
            'duplicate registered Aether identity public keys exist across accounts; resolve ownership before applying migration 0003'
            USING ERRCODE = '23505';
    END IF;
END
$migration$;

DROP INDEX account_devices_identity_key_idx;

CREATE UNIQUE INDEX account_devices_identity_key_idx
    ON account_devices(identity_public_key);
