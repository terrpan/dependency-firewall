ALTER TABLE upstreams
	DROP CONSTRAINT IF EXISTS upstreams_auth_type_check,
	DROP COLUMN IF EXISTS auth_updated_at,
	DROP COLUMN IF EXISTS auth_secret,
	DROP COLUMN IF EXISTS auth_username,
	DROP COLUMN IF EXISTS auth_type;
