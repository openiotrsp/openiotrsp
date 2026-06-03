ALTER TABLE notifications
	ADD COLUMN sequence_number bigint;

WITH numbered AS (
	SELECT id, row_number() OVER (
		PARTITION BY tenant_id, eid
		ORDER BY created_at, id
	) AS sequence_number
	FROM notifications
)
UPDATE notifications
SET sequence_number = numbered.sequence_number
FROM numbered
WHERE notifications.id = numbered.id;

ALTER TABLE notifications
	ALTER COLUMN sequence_number SET NOT NULL,
	ADD CONSTRAINT notifications_sequence_number_positive CHECK (sequence_number > 0);

CREATE UNIQUE INDEX notifications_sequence_idx ON notifications (tenant_id, eid, sequence_number);

DROP INDEX IF EXISTS notifications_device_idx;
CREATE INDEX notifications_device_idx ON notifications (tenant_id, eid, sequence_number);
