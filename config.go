package main

// A very small INI reader for the watcher's configuration. It holds credentials,
// so it is expected to be mode 0600 and is refused if it is readable by others.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type Section struct {
	Name string
	Keys map[string]string
}

func (s *Section) Get(k string) string { return s.Keys[k] }

func (s *Section) Bool(k string) bool {
	switch strings.ToLower(s.Keys[k]) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

func (s *Section) Duration(k string, def time.Duration) (time.Duration, error) {
	v := s.Keys[k]
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("[%s] %s: %v", s.Name, k, err)
	}
	return d, nil
}

type Config struct {
	sections []*Section
}

func (c *Config) Section(name string) *Section {
	for _, s := range c.sections {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return &Section{Name: name, Keys: map[string]string{}}
}

// NetworkSection returns the settings for one network, falling back to
// [network default] for anything it does not set.
func (c *Config) NetworkSection(name string) *Section {
	def := c.Section("network default")
	own := c.Section("network " + name)
	merged := &Section{Name: own.Name, Keys: map[string]string{}}
	for k, v := range def.Keys {
		merged.Keys[k] = v
	}
	for k, v := range own.Keys {
		merged.Keys[k] = v
	}
	return merged
}

// policyKeys are the only settings a policy file may carry. The credentials and
// anything that runs a command stay in the file only the watcher can read: a
// policy file is editable from the web interface, and nothing editable from there
// should be able to hand root a shell or read a password back.
var policyKeys = map[string]bool{
	"interval": true, "nick-cooldown": true, "nick": true, "client": true,
	"recover": true, "identify": true, "skip": true,
}

// MergePolicy layers a policy file over this configuration, ignoring keys a
// policy is not allowed to set.
func (c *Config) MergePolicy(p *Config) []string {
	var refused []string
	for _, src := range p.sections {
		var dst *Section
		if c.has(src.Name) {
			dst = c.Section(src.Name)
		} else {
			dst = &Section{Name: src.Name, Keys: map[string]string{}}
			c.sections = append(c.sections, dst)
		}
		for k, v := range src.Keys {
			if !policyKeys[k] {
				refused = append(refused, src.Name+"/"+k)
				continue
			}
			dst.Keys[k] = v
		}
	}
	return refused
}

func (c *Config) has(name string) bool {
	for _, s := range c.sections {
		if strings.EqualFold(s.Name, name) {
			return true
		}
	}
	return false
}

// LoadConfig reads a configuration that holds credentials, so it refuses a file
// others can read.
func LoadConfig(path string) (*Config, error) {
	return loadConfig(path, true)
}

// LoadPolicy reads a policy file, which holds no secrets and is expected to be
// writable by the web interface.
func LoadPolicy(path string) (*Config, error) {
	return loadConfig(path, false)
}

func loadConfig(path string, secret bool) (*Config, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if secret && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s holds a password and is readable by others: chmod 600 it", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	cur := &Section{Name: "", Keys: map[string]string{}}
	cfg.sections = append(cfg.sections, cur)

	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			cur = &Section{Name: strings.TrimSpace(s[1 : len(s)-1]), Keys: map[string]string{}}
			cfg.sections = append(cfg.sections, cur)
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		cur.Keys[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return cfg, sc.Err()
}
