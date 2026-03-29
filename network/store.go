package network

import (
	"encoding/json"
	"os"
)

// StoreData is the on-disk JSON format for persistent configuration.
type StoreData struct {
	Nicknames map[string]string `json:"nicknames"` // MAC → nickname
}

// LoadStore reads the store from path. Returns an empty store if the file does not exist.
func LoadStore(path string) (*StoreData, error) {
	s := &StoreData{Nicknames: make(map[string]string)}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return s, err
	}
	if s.Nicknames == nil {
		s.Nicknames = make(map[string]string)
	}
	return s, nil
}

// Save writes the store to path atomically (write to temp file, then rename).
func (s *StoreData) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
