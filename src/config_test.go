package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRuleStorageAndMigration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	old := filepath.Join(dir, "ConditionalDNSManager", "rules.json")
	if err := os.MkdirAll(filepath.Dir(old), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte(`[{"domain":"*.example.com","resolver":"10.0.0.53","active":false}]`), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules()
	if err != nil || len(rules) != 1 || rules[0].domain != "*.example.com" || rules[0].active {
		t.Fatalf("migration: %#v %v", rules, err)
	}
	path := filepath.Join(dir, "DNSManager", "rules.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	rules[0].active = true
	rules[0].publicIP = "142.110.0.0/16"
	if err := saveRules(rules); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRules()
	if err != nil || len(loaded) != 1 || !loaded[0].active || loaded[0].publicIP != "142.110.0.0/16" {
		t.Fatalf("saved rules: %#v %v", loaded, err)
	}
	policies := []policyRule{{Namespace: []string{".example.com", ".second.com"}, Resolver: "10.0.0.53"}}
	if err := saveApplied(loaded, policies); err != nil {
		t.Fatal(err)
	}
	applied, gotPolicies, err := loadApplied()
	if err != nil || len(applied) != 1 || applied[0].publicIP != loaded[0].publicIP || len(gotPolicies) != 1 || gotPolicies[0].Resolver != policies[0].Resolver || !slices.Equal(gotPolicies[0].Namespace, policies[0].Namespace) {
		t.Fatalf("applied state: %#v %#v %v", applied, gotPolicies, err)
	}
}

func TestWindowSizeStorage(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	want := windowSize{Width: 900, Height: 700}
	if err := saveWindowSize(want); err != nil {
		t.Fatal(err)
	}
	if got := loadWindowSize(); got != want {
		t.Fatalf("window size = %#v, want %#v", got, want)
	}
}

func TestThemeStorage(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	if got := loadTheme(); got != "" {
		t.Fatalf("default theme = %q", got)
	}
	if err := saveTheme("dark"); err != nil {
		t.Fatal(err)
	}
	if got := loadTheme(); got != "dark" {
		t.Fatalf("saved theme = %q", got)
	}
	if err := saveTheme("invalid"); err == nil {
		t.Fatal("accepted invalid theme")
	}
}
