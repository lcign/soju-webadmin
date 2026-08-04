package main

// Keeps the catalogs honest, which is what makes a contributed translation safe to
// accept: a missing key is allowed and falls back to English, an invented one is
// not — it is either a typo or a leftover from a key that was renamed.

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Keys as they appear in the templates: {{.T "x"}}, {{$.TH "y" ...}}, {{.TN "z" n}}.
var keyRe = regexp.MustCompile(`\{\{-?\s*\$?\.T[HN]?\s+"([^"]+)"`)

func loadBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := LoadLocales("")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// templateKeys collects every key the templates ask for, with the plural forms
// expanded, since TN looks up "<key>.one" and "<key>.other".
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
			// A TN call needs both forms; the call site is recognisable by ".TN ".
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

// The page titles are keys too, but they are named in the Go code, not in the
// templates. A network's name also arrives through .T and is meant to fall
// through untranslated, so only these fixed ones are checked.
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

// A partial translation must stay usable: whatever is missing falls back.
func TestFallbackToEnglish(t *testing.T) {
	b := loadBundle(t)
	l := b.Locale("it")
	if got := l.T("page.networks"); got != "Reti" {
		t.Errorf("italian page.networks = %q", got)
	}
	if got := l.T("does.not.exist.anywhere"); got != "does.not.exist.anywhere" {
		t.Errorf("an unknown key should show itself, got %q", got)
	}

	// A key only English has must come back in English, not as the key.
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
		{"de-DE,de;q=0.9", ""},      // no catalog: leave the default alone
		{"fr;q=0.8,it;q=0.9", "it"}, // quality decides the order
		{"", ""},
	} {
		if got := b.matchHeader(tc.header); got != tc.want {
			t.Errorf("Accept-Language %q -> %q, want %q", tc.header, got, tc.want)
		}
	}
}
