ALTER TABLE policies
    ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE policy_versions
    ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
