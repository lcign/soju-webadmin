package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var keyRe = regexp.MustCompile(`\{\{-?\s*\$?\.T[HN]?\s+"([^"]+)"`)

func loadBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := LoadLocales("")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func templateKeys(t *testing.T) map[string]bool {
	t.Helper()
	names, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, name := range names {
		raw, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, m := range keyRe.FindAllStringSubmatch(text, -1) {
			key := m[1]

			if strings.Contains(text, ".TN \""+key+"\"") {
				keys[key+".one"] = true
				keys[key+".other"] = true
				continue
			}
			keys[key] = true
		}
	}
	if len(keys) == 0 {
		t.Fatal("no keys found in the templates: the regexp no longer matches")
	}
	return keys
}

var titleKeys = []string{
	"page.networks", "page.add_network", "page.watcher", "page.console",
	"page.users", "page.sign_in", "page.delete_user", "page.error",
}

func TestEnglishCatalogCoversEveryKey(t *testing.T) {
	b := loadBundle(t)
	en := b.catalogs[defaultTag]
	for key := range templateKeys(t) {
		if en.Msgs[key] == "" {
			t.Errorf("%s.json has no %q, so that string would show as its key", defaultTag, key)
		}
	}
	for _, key := range titleKeys {
		if en.Msgs[key] == "" {
			t.Errorf("%s.json has no %q", defaultTag, key)
		}
	}
}

func TestTranslationsInventNoKeys(t *testing.T) {
	b := loadBundle(t)
	en := b.catalogs[defaultTag]
	for _, cat := range b.Languages() {
		if cat.Tag == defaultTag {
			continue
		}
		for key := range cat.Msgs {
			if key == nameKey {
				continue
			}
			if _, ok := en.Msgs[key]; !ok {
				t.Errorf("%s.json translates %q, which %s.json does not have: renamed or mistyped",
					cat.Tag, key, defaultTag)
			}
		}
		if cat.Msgs[nameKey] == "" {
			t.Errorf("%s.json has no %q: the switcher would show the tag instead of the language",
				cat.Tag, nameKey)
		}
	}
}

func TestFallbackToEnglish(t *testing.T) {
	b := loadBundle(t)
	l := b.Locale("it")
	if got := l.T("page.networks"); got != "Reti" {
		t.Errorf("italian page.networks = %q", got)
	}
	if got := l.T("does.not.exist.anywhere"); got != "does.not.exist.anywhere" {
		t.Errorf("an unknown key should show itself, got %q", got)
	}

	en := b.catalogs[defaultTag]
	en.Msgs["test.only.english"] = "Only here"
	defer delete(en.Msgs, "test.only.english")
	if got := l.T("test.only.english"); got != "Only here" {
		t.Errorf("fallback failed, got %q", got)
	}
}

func TestPlaceholdersAndPlurals(t *testing.T) {
	l := loadBundle(t).Locale("it")
	if got := l.T("sasl.reset_confirm", "network", "libera"); !strings.Contains(got, "libera") {
		t.Errorf("placeholder not filled: %q", got)
	}
	if got := l.TN("dash.detached", 1); !strings.Contains(got, "staccato)") {
		t.Errorf("singular: %q", got)
	}
	if got := l.TN("dash.detached", 3); !strings.Contains(got, "3 staccati") {
		t.Errorf("plural: %q", got)
	}
}

func TestAcceptLanguage(t *testing.T) {
	b := loadBundle(t)
	for _, tc := range []struct{ header, want string }{
		{"it-IT,it;q=0.9,en;q=0.8", "it"},
		{"en-GB,en;q=0.9", "en"},
		{"de-DE,de;q=0.9", ""},
		{"fr;q=0.8,it;q=0.9", "it"},
		{"", ""},
	} {
		if got := b.matchHeader(tc.header); got != tc.want {
			t.Errorf("Accept-Language %q -> %q, want %q", tc.header, got, tc.want)
		}
	}
}
