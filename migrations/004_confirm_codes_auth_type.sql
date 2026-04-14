ALTER TABLE confirm_codes ADD COLUMN IF NOT EXISTS auth_type TEXT NOT NULL DEFAULT 'verification';

DROP INDEX IF EXISTS idx_confirm_codes_device_recipient;
CREATE UNIQUE INDEX IF NOT EXISTS idx_confirm_codes_device_recipient_type ON confirm_codes (device_uid, recipient, auth_type);
