ALTER TABLE profile_state
	ADD COLUMN is_fallback boolean NOT NULL DEFAULT false;

DROP INDEX IF EXISTS profile_state_device_idx;
CREATE INDEX profile_state_device_idx ON profile_state (tenant_id, eid, is_enabled, is_fallback, iccid);
