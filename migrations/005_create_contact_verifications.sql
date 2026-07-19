CREATE TABLE IF NOT EXISTS contact_verifications (
    id             BIGSERIAL PRIMARY KEY,
    creation_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_date    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_type   TEXT NOT NULL CHECK (contact_type IN ('email', 'phone')),
    recipient      TEXT NOT NULL,
    device_uid     TEXT NOT NULL,
    provider       TEXT,
    allow_fallback BOOLEAN NOT NULL DEFAULT TRUE,
    status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'cancelled', 'expired')),
    code           TEXT NOT NULL,
    counter        INTEGER NOT NULL DEFAULT 0,
    sent_ts        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL,
    confirmed_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_contact_verifications_user ON contact_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_contact_verifications_status ON contact_verifications(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_contact_verifications_pending_contact
    ON contact_verifications(user_id, contact_type)
    WHERE status = 'pending';
