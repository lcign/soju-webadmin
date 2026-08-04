package main

// Translations for the fixed text of the pages — labels, buttons, headings, the
// explanations. Nothing else is translated: what soju answers (BouncerServ
// replies, SASL and channel status, its error messages) is its own wording and is
// shown as it arrives, and so are the messages this program prints after an
// action.
//
// A language is one file in locales/, found by its name, listed in the switcher on
// its own. Adding one takes no Go at all; -locales-dir loads them from disk
// instead, so a translation can be tried without rebuilding.

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed locales/*.json
var localeFS embed.FS

const langCookie = "soju_webadmin_lang"

// defaultTag is the language the catalogs are written in, and the fallback for any
// key a translation has not covered.
const defaultTag = "en"

// nameKey holds the language's own name, for the switcher: a reader looking for
// their language wants to see it written in it.
const nameKey = "_name"

type Catalog struct {
	Tag  string
	Name string
	Msgs map[string]string
}

type Bundle struct {
	catalogs map[string]*Catalog
	tags     []string // sorted, for a stable switcher
}

// LoadLocales reads the catalogs. With dir empty they come from the binary;
// otherwise from that directory, which is how a translation gets tried before it
// is contributed.
func LoadLocales(dir string) (*Bundle, error) {
	var fsys fs.FS = localeFS
	pattern := "locales/*.json"
	if dir != "" {
		fsys = os.DirFS(dir)
		pattern = "*.json"
	}
	names, err := fs.Glob(fsys, pattern)
	if err != nil {
		return nil, err
	}

	b := &Bundle{catalogs: map[string]*Catalog{}}
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		msgs := map[string]string{}
		if err := json.Unmarshal(raw, &msgs); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		tag := strings.TrimSuffix(filepath.Base(name), ".json")
		cat := &Catalog{Tag: tag, Name: msgs[nameKey], Msgs: msgs}
		if cat.Name == "" {
			cat.Name = tag
		}
		b.catalogs[tag] = cat
		b.tags = append(b.tags, tag)
	}
	if b.catalogs[defaultTag] == nil {
		return nil, fmt.Errorf("no %s.json among the catalogs: there would be nothing to fall back to", defaultTag)
	}
	sort.Strings(b.tags)
	return b, nil
}

// Languages lists what a reader can pick.
func (b *Bundle) Languages() []*Catalog {
	out := make([]*Catalog, 0, len(b.tags))
	for _, t := range b.tags {
		out = append(out, b.catalogs[t])
	}
	return out
}

func (b *Bundle) Has(tag string) bool { return b.catalogs[tag] != nil }

// Locale answers for one request.
type Locale struct {
	bundle *Bundle
	cat    *Catalog
	fb     *Catalog
}

func (b *Bundle) Locale(tag string) *Locale {
	cat := b.catalogs[tag]
	if cat == nil {
		cat = b.catalogs[defaultTag]
	}
	return &Locale{bundle: b, cat: cat, fb: b.catalogs[defaultTag]}
}

// Pick decides the language: the instance default, then what the browser asks
// for, then the reader's own choice, which wins.
func (b *Bundle) Pick(r *http.Request, deflt string) *Locale {
	tag := defaultTag
	if b.Has(deflt) {
		tag = deflt
	}
	if t := b.matchHeader(r.Header.Get("Accept-Language")); t != "" {
		tag = t
	}
	if c, err := r.Cookie(langCookie); err == nil && b.Has(c.Value) {
		tag = c.Value
	}
	return b.Locale(tag)
}

// matchHeader takes the first language of Accept-Language there is a catalog for.
// Quality values are read only to order the candidates.
func (b *Bundle) matchHeader(header string) string {
	type pref struct {
		tag string
		q   float64
	}
	var prefs []pref
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, q := part, 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			tag = strings.TrimSpace(part[:i])
			if _, after, ok := strings.Cut(part[i+1:], "q="); ok {
				if v, err := strconv.ParseFloat(strings.TrimSpace(after), 64); err == nil {
					q = v
				}
			}
		}
		// "it-CH" and "it" are the same catalog here: there are no regional variants.
		if i := strings.Index(tag, "-"); i >= 0 {
			tag = tag[:i]
		}
		prefs = append(prefs, pref{strings.ToLower(tag), q})
	}
	sort.SliceStable(prefs, func(i, j int) bool { return prefs[i].q > prefs[j].q })
	for _, p := range prefs {
		if b.Has(p.tag) {
			return p.tag
		}
	}
	return ""
}

func (l *Locale) Tag() string               { return l.cat.Tag }
func (l *Locale) Languages() []*Catalog     { return l.bundle.Languages() }
func (l *Locale) Current() *Catalog         { return l.cat }
func (l *Locale) IsCurrent(c *Catalog) bool { return c.Tag == l.cat.Tag }

// lookup falls back to the language the catalogs are written in, and finally to
// the key itself: a translation may be partial, and a page must still read.
func (l *Locale) lookup(key string) string {
	if s, ok := l.cat.Msgs[key]; ok && s != "" {
		return s
	}
	if s, ok := l.fb.Msgs[key]; ok && s != "" {
		return s
	}
	return key
}

// fill replaces {name} placeholders. Named, not positional: a translator who
// reorders a sentence cannot swap two values by accident.
func fill(s string, kv []string) string {
	for i := 0; i+1 < len(kv); i += 2 {
		s = strings.ReplaceAll(s, "{"+kv[i]+"}", kv[i+1])
	}
	return s
}

// T is the plain text of a key, escaped like any other string by the template.
func (l *Locale) T(key string, kv ...string) string {
	return fill(l.lookup(key), kv)
}

// TH is for the few passages that carry inline markup — a <strong> inside a
// warning. Its value is trusted exactly as much as the templates are: catalogs
// ship with the program, or come from a directory its operator chose.
func (l *Locale) TH(key string, kv ...string) template.HTML {
	return template.HTML(fill(l.lookup(key), kv))
}

// TN picks between "<key>.one" and "<key>.other" and fills in {n}. Enough for
// English and Italian; a language with real plural categories (Polish, Russian,
// Arabic) would need CLDR rules, and with them the first outside dependency this
// program has.
func (l *Locale) TN(key string, n int, kv ...string) string {
	form := ".other"
	if n == 1 {
		form = ".one"
	}
	return fill(l.lookup(key+form), append([]string{"n", strconv.Itoa(n)}, kv...))
}
