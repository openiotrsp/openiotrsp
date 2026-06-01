CREATE TABLE devices (
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	next_sequence_number bigint NOT NULL DEFAULT 1 CHECK (next_sequence_number > 0),
	next_euicc_package_counter bigint NOT NULL DEFAULT 1 CHECK (next_euicc_package_counter > 0),
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (tenant_id, eid)
);

CREATE TABLE profile_state (
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	iccid text NOT NULL,
	is_enabled boolean NOT NULL,
	smdp_address text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (tenant_id, eid, iccid),
	FOREIGN KEY (tenant_id, eid) REFERENCES devices (tenant_id, eid) ON DELETE CASCADE
);

CREATE INDEX profile_state_device_idx ON profile_state (tenant_id, eid, is_enabled, iccid);

CREATE TABLE operations (
	id bigserial PRIMARY KEY,
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	sequence_number bigint NOT NULL CHECK (sequence_number > 0),
	kind text NOT NULL,
	payload bytea NOT NULL,
	status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in-flight', 'done', 'failed')),
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (tenant_id, eid, sequence_number),
	FOREIGN KEY (tenant_id, eid) REFERENCES devices (tenant_id, eid) ON DELETE CASCADE
);

CREATE INDEX operations_poll_idx ON operations (tenant_id, eid, status, sequence_number);

CREATE TABLE operation_results (
	id bigserial PRIMARY KEY,
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	operation_id bigint REFERENCES operations (id) ON DELETE SET NULL,
	sequence_number bigint NOT NULL CHECK (sequence_number > 0),
	status text NOT NULL CHECK (status IN ('done', 'failed')),
	payload bytea NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (tenant_id, eid, sequence_number),
	FOREIGN KEY (tenant_id, eid) REFERENCES devices (tenant_id, eid) ON DELETE CASCADE
);

CREATE TABLE eim_config (
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eim_id text NOT NULL,
	config_payload bytea NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (tenant_id, eim_id)
);

CREATE TABLE notifications (
	id bigserial PRIMARY KEY,
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	kind text NOT NULL,
	payload bytea NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	FOREIGN KEY (tenant_id, eid) REFERENCES devices (tenant_id, eid) ON DELETE CASCADE
);

CREATE INDEX notifications_device_idx ON notifications (tenant_id, eid, created_at);
