package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type storedRule struct {
	Domain   string `json:"domain"`
	Resolver string `json:"resolver"`
	Active   bool   `json:"active"`
	PublicIP string `json:"public_ip,omitempty"`
}

type windowSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

func themePath() (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "theme.json"), nil
}

func loadTheme() string {
	path, err := themePath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var theme string
	if json.Unmarshal(b, &theme) == nil && (theme == "light" || theme == "dark") {
		return theme
	}
	return ""
}

func saveTheme(theme string) error {
	if theme != "light" && theme != "dark" {
		return fmt.Errorf("invalid theme")
	}
	path, err := themePath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(theme)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func windowSizePath() (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "window.json"), nil
}

func loadWindowSize() windowSize {
	size := windowSize{Width: 1020, Height: 625}
	path, err := windowSizePath()
	if err != nil {
		return size
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return size
	}
	var saved windowSize
	if json.Unmarshal(b, &saved) == nil && saved.Width >= 680 && saved.Height >= 500 {
		return saved
	}
	return size
}

func saveWindowSize(size windowSize) error {
	path, err := windowSizePath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(size)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "DNSManager", "rules.json"), nil
}
func saveRules(rules []rule) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	return writeRules(path, rules)
}

func appliedConfigPath() (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "applied.json"), nil
}

func writeRules(path string, rules []rule) error {
	var err error
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	saved := make([]storedRule, 0, len(rules))
	for _, r := range rules {
		saved = append(saved, storedRule{r.domain, r.resolver, r.active, r.publicIP})
	}
	b, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "rules-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

type appliedState struct {
	Rules    []storedRule `json:"rules"`
	Policies []policyRule `json:"policies"`
}

func saveApplied(rules []rule, policies []policyRule) error {
	path, err := appliedConfigPath()
	if err != nil {
		return err
	}
	state := appliedState{Policies: policies}
	for _, r := range rules {
		state.Rules = append(state.Rules, storedRule{r.domain, r.resolver, r.active, r.publicIP})
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "applied-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func loadApplied() ([]rule, []policyRule, error) {
	path, err := appliedConfigPath()
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var state appliedState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, nil, err
	}
	rules := make([]rule, 0, len(state.Rules))
	for _, r := range state.Rules {
		rules = append(rules, rule{domain: r.Domain, resolver: r.Resolver, protocol: "UDP", active: r.Active, publicIP: r.PublicIP})
	}
	return rules, state.Policies, nil
}
func loadRules() ([]rule, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		legacy := filepath.Join(filepath.Dir(filepath.Dir(path)), "ConditionalDNSManager", "rules.json")
		b, err = os.ReadFile(legacy)
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read previous saved rules: %w", err)
		}
		result, err := decodeRules(b)
		if err != nil {
			return nil, err
		}
		if err = saveRules(result); err != nil {
			return result, fmt.Errorf("migrate saved rules: %w", err)
		}
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeRules(b)
}

func decodeRules(b []byte) ([]rule, error) {
	var saved []storedRule
	if err := json.Unmarshal(b, &saved); err != nil {
		return nil, fmt.Errorf("read saved rules: %w", err)
	}
	result := make([]rule, 0, len(saved))
	for _, r := range saved {
		result = append(result, rule{domain: r.Domain, resolver: r.Resolver, active: r.Active, publicIP: r.PublicIP, protocol: "UDP"})
	}
	return result, nil
}
