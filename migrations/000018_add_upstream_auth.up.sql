ALTER TABLE upstreams
	ADD COLUMN auth_type text NOT NULL DEFAULT 'none',
	ADD COLUMN auth_username text,
	ADD COLUMN auth_secret jsonb,
	ADD COLUMN auth_updated_at timestamptz,
	ADD CONSTRAINT upstreams_auth_type_check CHECK (auth_type IN ('none', 'basic', 'bearer_token'));
