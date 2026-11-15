ALTER TABLE euicc_state
	ADD COLUMN rules_authorisation_table bytea;

ALTER TABLE profile_state
	ADD COLUMN profile_class integer;
