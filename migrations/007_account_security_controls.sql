-- Keep the standalone auth-service test and development schema aligned with
-- the account-security fields introduced in the shared database migrations.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS two_factor_secret_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS two_factor_confirmed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ;

UPDATE users
SET password_updated_at = update_date
WHERE password IS NOT NULL
  AND password_updated_at IS NULL;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS device_uid TEXT,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_sessions_user_active
    ON sessions (user_id, last_seen_at DESC)
    WHERE blocked = FALSE;
