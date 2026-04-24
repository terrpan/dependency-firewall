UPDATE policies
SET
    config = (config - 'enforce') ||
             CASE
                 WHEN lower(config->>'enforce') = 'warn' THEN jsonb_build_object('dry_run', true)
                 ELSE '{}'::jsonb
             END,
    updated_at = now()
WHERE config ? 'enforce';

UPDATE policy_versions
SET
    config = (config - 'enforce') ||
             CASE
                 WHEN lower(config->>'enforce') = 'warn' THEN jsonb_build_object('dry_run', true)
                 ELSE '{}'::jsonb
             END
WHERE config ? 'enforce';
