ALTER TABLE decisions
    DROP COLUMN IF EXISTS policy_hash;

DROP TABLE IF EXISTS tenant_policy_revisions;
