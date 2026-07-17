package dataact

const (
	// SchemaVersion is the export bundle schema version understood by this importer.
	SchemaVersion = "1.0.0"
)

// Export entity file names inside the bundle ZIP.
const (
	FileTenant         = "tenant.json"
	FileSIMs           = "sims.ndjson"
	FileDevices        = "devices.ndjson"
	FileProfileState   = "profile_state.ndjson"
	FileAssociatedEIM  = "associated_eim.ndjson"
	FileEUICCState     = "euicc_state.ndjson"
	FileOperations     = "operations.ndjson"
	FileNotifications  = "notifications.ndjson"
	FileFallbackPolicy = "fallback_policy.ndjson"
	FileProfileLabels  = "profile_labels.ndjson"
	FileCommandJournal = "command_journal.ndjson"
	FileREADME         = "README.md"
	FileManifest       = "manifest.json"
)
