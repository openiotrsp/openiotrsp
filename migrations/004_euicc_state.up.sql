CREATE TABLE euicc_state (
	tenant_id text NOT NULL DEFAULT 'openiotrsp',
	eid text NOT NULL,
	eid_value bytea,
	default_smdp_address text NOT NULL DEFAULT '',
	root_smds_address text NOT NULL DEFAULT '',
	euicc_info1 bytea,
	euicc_info2 bytea,
	ipa_capabilities bytea,
	device_info bytea,
	eum_certificate bytea,
	euicc_certificate bytea,
	certificate_identifiers jsonb NOT NULL DEFAULT '[]'::jsonb,
	raw_payload bytea,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (tenant_id, eid),
	FOREIGN KEY (tenant_id, eid) REFERENCES devices (tenant_id, eid) ON DELETE CASCADE
);
