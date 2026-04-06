CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    creation_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    update_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tg_id           BIGINT,
    password        TEXT,
    email           TEXT,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    phone           TEXT,
    phone_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    role            TEXT NOT NULL DEFAULT 'user',
    verify_status   TEXT NOT NULL DEFAULT 'unverified'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users (phone) WHERE phone IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tg_id ON users (tg_id) WHERE tg_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_verify_status ON users (verify_status);
