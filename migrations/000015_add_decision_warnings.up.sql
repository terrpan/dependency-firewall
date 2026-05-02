ALTER TABLE decisions
    ADD COLUMN warnings TEXT[] NOT NULL DEFAULT '{}';
