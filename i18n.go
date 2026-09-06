package main

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

const defaultTag = "en"

const nameKey = "_name"

type Catalog struct {
	Tag  string
	Name string
	Msgs map[string]string
}

type Bundle struct {
	catalogs map[string]*Catalog
	tags     []string
}

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

func (b *Bundle) Languages() []*Catalog {
	out := make([]*Catalog, 0, len(b.tags))
	for _, t := range b.tags {
		out = append(out, b.catalogs[t])
	}
	return out
}

func (b *Bundle) Has(tag string) bool { return b.catalogs[tag] != nil }

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

func (l *Locale) lookup(key string) string {
	if s, ok := l.cat.Msgs[key]; ok && s != "" {
		return s
	}
	if s, ok := l.fb.Msgs[key]; ok && s != "" {
		return s
	}
	return key
}

func fill(s string, kv []string) string {
	for i := 0; i+1 < len(kv); i += 2 {
		s = strings.ReplaceAll(s, "{"+kv[i]+"}", kv[i+1])
	}
	return s
}

func (l *Locale) T(key string, kv ...string) string {
	return fill(l.lookup(key), kv)
}

func (l *Locale) TH(key string, kv ...string) template.HTML {
	return template.HTML(fill(l.lookup(key), kv))
}

func (l *Locale) TN(key string, n int, kv ...string) string {
	form := ".other"
	if n == 1 {
		form = ".one"
	}
	return fill(l.lookup(key+form), append([]string{"n", strconv.Itoa(n)}, kv...))
}
