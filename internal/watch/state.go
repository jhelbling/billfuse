package watch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// State survives restarts so baselines, "seen" sets and cooldowns persist.
type State struct {
	Cycles   int                  `json:"cycles"`
	Baseline map[string]float64   `json:"baseline_usd_per_hour"` // EWMA per scope
	Seen     map[string]time.Time `json:"seen"`                  // first time a region/model/credential was seen
	Active   map[string]bool      `json:"active"`                // threshold alerts currently firing
	LastSent map[string]time.Time `json:"last_sent"`
	Acted    map[string]time.Time `json:"acted"` // scope|date -> when the kill switch tripped
	path     string
}

func LoadState(path string) *State {
	s := &State{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, s)
	}
	if s.Baseline == nil {
		s.Baseline = map[string]float64{}
	}
	if s.Seen == nil {
		s.Seen = map[string]time.Time{}
	}
	if s.Active == nil {
		s.Active = map[string]bool{}
	}
	if s.LastSent == nil {
		s.LastSent = map[string]time.Time{}
	}
	if s.Acted == nil {
		s.Acted = map[string]time.Time{}
	}
	return s
}

func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
