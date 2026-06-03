DROP INDEX IF EXISTS notifications_device_idx;
DROP INDEX IF EXISTS notifications_sequence_idx;

ALTER TABLE notifications
	DROP CONSTRAINT IF EXISTS notifications_sequence_number_positive,
	DROP COLUMN IF EXISTS sequence_number;

CREATE INDEX notifications_device_idx ON notifications (tenant_id, eid, created_at);
