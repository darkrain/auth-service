CREATE TABLE IF NOT EXISTS sessions (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token         TEXT NOT NULL,
    creation_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expire_date   TIMESTAMPTZ NOT NULL,
    auth_type     TEXT NOT NULL DEFAULT 'password',
    ip            TEXT,
    blocked       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token ON sessions (token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expire_date ON sessions (expire_date);
CREATE INDEX IF NOT EXISTS idx_sessions_blocked ON sessions (blocked);
