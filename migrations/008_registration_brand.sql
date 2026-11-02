-- A full platform deployment supplies this column in migration 203.
-- Standalone auth databases need the same persisted registration identity.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public'
                   AND table_name='users' AND column_name='registration_brand') THEN
        ALTER TABLE users ADD COLUMN registration_brand TEXT NOT NULL DEFAULT 'iamfree'
            CHECK (registration_brand IN ('iamfree', 'topmember'));
        UPDATE users SET registration_brand='topmember' WHERE role='client';
    END IF;
END;
$$;
