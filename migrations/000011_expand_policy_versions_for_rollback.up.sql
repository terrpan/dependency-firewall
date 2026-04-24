ALTER TABLE policy_versions
    ADD COLUMN name TEXT,
    ADD COLUMN type TEXT,
    ADD COLUMN action TEXT,
    ADD COLUMN priority INTEGER,
    ADD COLUMN enabled BOOLEAN;

UPDATE policy_versions pv
SET
    name = p.name,
    type = p.type,
    action = p.action,
    priority = p.priority,
    enabled = p.enabled
FROM policies p
WHERE p.id = pv.policy_id;

ALTER TABLE policy_versions
    ALTER COLUMN name SET NOT NULL,
    ALTER COLUMN type SET NOT NULL,
    ALTER COLUMN action SET NOT NULL,
    ALTER COLUMN priority SET NOT NULL,
    ALTER COLUMN enabled SET NOT NULL;
