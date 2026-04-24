ALTER TABLE policy_versions
    DROP COLUMN IF EXISTS schema_version;

ALTER TABLE policies
    DROP COLUMN IF EXISTS schema_version;
