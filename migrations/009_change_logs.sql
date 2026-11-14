-- Administrative account blocks are audited in the platform's change_logs
-- (application database migration 16). Standalone auth databases need the
-- same table; on a full platform deployment this changes nothing.
CREATE TABLE IF NOT EXISTS change_logs (
    id            BIGSERIAL PRIMARY KEY,
    creation_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    table_name    TEXT NOT NULL,
    object_id     BIGINT,
    ip            TEXT,
    auth_token    TEXT,
    value_from    TEXT,
    value_to      TEXT,
    user_id       BIGINT REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_change_logs_object_id ON change_logs (object_id);
