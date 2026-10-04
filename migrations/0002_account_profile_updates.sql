ALTER TABLE accounts
    ADD COLUMN pending_email TEXT,
    ADD COLUMN pending_email_normalized TEXT,
    ADD CONSTRAINT accounts_email_normalized_check
        CHECK (email_normalized = lower(email)),
    ADD CONSTRAINT accounts_pending_email_pair_check
        CHECK ((pending_email IS NULL) = (pending_email_normalized IS NULL)),
    ADD CONSTRAINT accounts_pending_email_normalized_check
        CHECK (pending_email_normalized IS NULL OR pending_email_normalized = lower(pending_email));

CREATE UNIQUE INDEX accounts_pending_email_normalized_idx
    ON accounts(pending_email_normalized)
    WHERE pending_email_normalized IS NOT NULL;

ALTER TABLE email_verification_challenges
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'signup',
    ADD COLUMN target_email_normalized TEXT;

UPDATE email_verification_challenges AS challenge
SET target_email_normalized = account.email_normalized
FROM accounts AS account
WHERE account.id = challenge.account_id;

ALTER TABLE email_verification_challenges
    ALTER COLUMN target_email_normalized SET NOT NULL,
    ADD CONSTRAINT email_verification_challenges_purpose_check
        CHECK (purpose IN ('signup', 'email_change')),
    ADD CONSTRAINT email_verification_challenges_target_email_normalized_check
        CHECK (target_email_normalized = lower(target_email_normalized));
