CREATE TABLE IF NOT EXISTS confirm_codes (
    device_uid  TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    code        TEXT NOT NULL,
    counter     INT NOT NULL DEFAULT 0,
    sent_ts     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_confirm_codes_device_recipient ON confirm_codes (device_uid, recipient);
