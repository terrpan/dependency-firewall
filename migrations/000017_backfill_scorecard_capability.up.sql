UPDATE upstreams
SET capabilities = ARRAY['publish_time', 'licenses', 'vulnerability_lookup', 'scorecard_lookup']::TEXT[]
WHERE ecosystem = 'npm'
  AND capabilities = ARRAY['publish_time', 'licenses', 'vulnerability_lookup']::TEXT[];
