CREATE INDEX browser_session_exchanges_hosted_poll_idx
    ON browser_session_exchanges(state_hash, code_challenge_hash, created_at DESC)
    WHERE consumed_at IS NULL;
