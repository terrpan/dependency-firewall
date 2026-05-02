ALTER TABLE upstreams
    ADD COLUMN capabilities TEXT[] NOT NULL DEFAULT '{}';

UPDATE upstreams
SET capabilities = CASE ecosystem
    WHEN 'npm' THEN ARRAY['publish_time', 'licenses', 'vulnerability_lookup']::TEXT[]
    WHEN 'oci' THEN ARRAY['manifest_digest_lookup']::TEXT[]
    ELSE ARRAY[]::TEXT[]
END;
