DROP INDEX IF EXISTS profile_state_device_idx;
CREATE INDEX profile_state_device_idx ON profile_state (tenant_id, eid, is_enabled, iccid);

ALTER TABLE profile_state
	DROP COLUMN is_fallback;
