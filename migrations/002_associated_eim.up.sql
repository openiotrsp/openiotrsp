CREATE TABLE associated_eim (
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	eim_id text NOT NULL,
	eim_id_type bigint,
	config_payload bytea NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (tenant_id, eid, eim_id),
	FOREIGN KEY (tenant_id, eid) REFERENCES devices (tenant_id, eid) ON DELETE CASCADE
);

CREATE INDEX associated_eim_device_idx ON associated_eim (tenant_id, eid, eim_id);
