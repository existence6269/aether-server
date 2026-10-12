CREATE TABLE account_signup_rate_limits (
    window_start TIMESTAMPTZ PRIMARY KEY,
    signup_count INTEGER NOT NULL CHECK (signup_count BETWEEN 1 AND 30)
);
