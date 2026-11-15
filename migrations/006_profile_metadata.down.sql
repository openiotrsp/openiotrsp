ALTER TABLE profile_state
	DROP COLUMN IF EXISTS profile_class;

ALTER TABLE euicc_state
	DROP COLUMN IF EXISTS rules_authorisation_table;
