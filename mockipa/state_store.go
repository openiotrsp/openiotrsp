package mockipa

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// StateStore persists mock IPA device inventory across restarts.
type StateStore struct {
	path string
	mu   sync.Mutex
}

type persistedState struct {
	DefaultSMDP             string                       `json:"defaultSmdp,omitempty"`
	RootSMDS                string                       `json:"rootSmds,omitempty"`
	Profiles                map[string]persistedProfile  `json:"profiles,omitempty"`
	NextNotificationSeq     int64                        `json:"nextNotificationSeq,omitempty"`
	IndirectProfileDownload   bool                         `json:"indirectProfileDownload,omitempty"`
	ChainPresentationRequired bool                         `json:"chainPresentationRequired,omitempty"`
	ChainPresented            bool                         `json:"chainPresented,omitempty"`
}

type persistedProfile struct {
	ICCIDHex string `json:"iccidHex"`
	SMDP     string `json:"smdp,omitempty"`
	Enabled  bool   `json:"enabled"`
	Fallback bool   `json:"fallback,omitempty"`
}

// OpenStateStore loads or creates the JSON state file at path.
func OpenStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, errors.New("mockipa: missing state path")
	}
	store := &StateStore{path: path}
	if err := store.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return store, nil
}

func (s *StateStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("mockipa: decode state: %w", err)
	}
	return nil
}

// Apply restores runner fields from disk.
func (s *StateStore) Apply(device *DeviceState, nextSeq *int64, indirect *bool, chainPresentationRequired *bool, chainPresented *bool) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("mockipa: decode state: %w", err)
	}
	if device != nil {
		device.DefaultSMDP = state.DefaultSMDP
		if state.RootSMDS != "" {
			device.RootSMDS = state.RootSMDS
		}
		if device.Profiles == nil {
			device.Profiles = make(map[string]profileRecord)
		}
		for key, record := range state.Profiles {
			iccid, decodeErr := hex.DecodeString(record.ICCIDHex)
			if decodeErr != nil {
				continue
			}
			device.Profiles[key] = profileRecord{
				ICCID:    iccid,
				SMDP:     record.SMDP,
				Enabled:  record.Enabled,
				Fallback: record.Fallback,
			}
		}
	}
	if nextSeq != nil && state.NextNotificationSeq > 0 {
		*nextSeq = state.NextNotificationSeq
	}
	if indirect != nil {
		*indirect = state.IndirectProfileDownload
	}
	if chainPresented != nil {
		*chainPresented = state.ChainPresented
	}
	if chainPresentationRequired != nil {
		*chainPresentationRequired = state.ChainPresentationRequired
	}
	return nil
}

// Save writes the current runner state to disk.
func (s *StateStore) Save(device *DeviceState, nextSeq int64, indirect bool, chainPresentationRequired bool, chainPresented bool) error {
	if s == nil {
		return nil
	}
	state := persistedState{
		DefaultSMDP:             "",
		RootSMDS:                "smds.example",
		Profiles:                map[string]persistedProfile{},
		NextNotificationSeq:     nextSeq,
		IndirectProfileDownload:   indirect,
		ChainPresentationRequired: chainPresentationRequired,
		ChainPresented:            chainPresented,
	}
	if device != nil {
		state.DefaultSMDP = device.DefaultSMDP
		if device.RootSMDS != "" {
			state.RootSMDS = device.RootSMDS
		}
		for key, record := range device.Profiles {
			state.Profiles[key] = persistedProfile{
				ICCIDHex: hex.EncodeToString(record.ICCID),
				SMDP:     record.SMDP,
				Enabled:  record.Enabled,
				Fallback: record.Fallback,
			}
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
