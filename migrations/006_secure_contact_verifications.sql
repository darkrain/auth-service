ALTER TABLE contact_verifications ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'verification';
ALTER TABLE contact_verifications ADD COLUMN IF NOT EXISTS code_hash TEXT;

-- Existing pending rows were created by the temporary implementation that
-- persisted a plaintext code. They cannot be safely upgraded and must be
-- requested again.
UPDATE contact_verifications
SET status = 'expired', code_hash = ''
WHERE code_hash IS NULL;

ALTER TABLE contact_verifications ALTER COLUMN code_hash SET NOT NULL;
ALTER TABLE contact_verifications DROP COLUMN IF EXISTS code;
DROP INDEX IF EXISTS idx_contact_verifications_pending_contact;
