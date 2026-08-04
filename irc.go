package main

// A minimal IRC message codec — only what this program needs: tags (for the
// standard-replies soju sends), prefix, command, params. There is no attempt at
// covering the whole protocol.

import (
	"errors"
	"strings"
)

type Message struct {
	Tags    map[string]string
	Prefix  string
	Command string
	Params  []string
}

// Param returns the i-th parameter, or "" when it is absent, so callers can
// read optional parameters without bounds checks.
func (m *Message) Param(i int) string {
	if i < 0 || i >= len(m.Params) {
		return ""
	}
	return m.Params[i]
}

// Nick returns the nickname part of the prefix ("BouncerServ!…" -> "BouncerServ").
func (m *Message) Nick() string {
	if i := strings.IndexAny(m.Prefix, "!@"); i >= 0 {
		return m.Prefix[:i]
	}
	return m.Prefix
}

func parseMessage(line string) (*Message, error) {
	line = strings.TrimRight(line, "\r\n")
	m := &Message{}

	if strings.HasPrefix(line, "@") {
		part, rest, ok := cut(line[1:], " ")
		if !ok {
			return nil, errors.New("malformed message: tags without command")
		}
		m.Tags = parseTags(part)
		line = strings.TrimLeft(rest, " ")
	}

	if strings.HasPrefix(line, ":") {
		part, rest, ok := cut(line[1:], " ")
		if !ok {
			return nil, errors.New("malformed message: prefix without command")
		}
		m.Prefix = part
		line = strings.TrimLeft(rest, " ")
	}

	// The trailing parameter starts at " :" and is the only one allowed to hold
	// spaces, so it has to be split off before the others.
	var trailing string
	hasTrailing := false
	if i := strings.Index(line, " :"); i >= 0 {
		trailing, hasTrailing = line[i+2:], true
		line = line[:i]
	} else if strings.HasPrefix(line, ":") {
		trailing, hasTrailing = line[1:], true
		line = ""
	}

	fields := strings.Fields(line)
	if len(fields) > 0 {
		m.Command = strings.ToUpper(fields[0])
		m.Params = fields[1:]
	}
	if hasTrailing {
		m.Params = append(m.Params, trailing)
	}
	if m.Command == "" {
		return nil, errors.New("malformed message: no command")
	}
	return m, nil
}

func formatMessage(command string, params ...string) string {
	var b strings.Builder
	b.WriteString(command)
	for i, p := range params {
		b.WriteString(" ")
		// A parameter that is empty, holds a space or opens with ':' can only be
		// expressed as the trailing one, which must come last.
		if i == len(params)-1 && (p == "" || strings.ContainsAny(p, " ") || strings.HasPrefix(p, ":")) {
			b.WriteString(":")
		}
		b.WriteString(p)
	}
	return b.String()
}

// Tag and attribute values share one escaping scheme: soju.im/bouncer-networks
// encodes network attributes exactly like message tags.

func parseTags(s string) map[string]string {
	tags := map[string]string{}
	for _, kv := range strings.Split(s, ";") {
		if kv == "" {
			continue
		}
		k, v, _ := cut(kv, "=")
		tags[k] = unescapeTagValue(v)
	}
	return tags
}

func formatTags(tags map[string]string) string {
	var parts []string
	for k, v := range tags {
		parts = append(parts, k+"="+escapeTagValue(v))
	}
	return strings.Join(parts, ";")
}

func unescapeTagValue(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i == len(v)-1 {
			b.WriteByte(v[i])
			continue
		}
		i++
		switch v[i] {
		case ':':
			b.WriteByte(';')
		case 's':
			b.WriteByte(' ')
		case 'r':
			b.WriteByte('\r')
		case 'n':
			b.WriteByte('\n')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte(v[i]) // an unknown escape drops the backslash
		}
	}
	return b.String()
}

func escapeTagValue(v string) string {
	r := strings.NewReplacer(
		"\\", "\\\\",
		";", "\\:",
		" ", "\\s",
		"\r", "\\r",
		"\n", "\\n",
	)
	return r.Replace(v)
}

func cut(s, sep string) (before, after string, found bool) {
	return strings.Cut(s, sep)
}

// splitWords splits a line the way BouncerServ does: spaces separate words,
// single or double quotes group them, and a backslash escapes the next
// character. The console uses it so what is typed there behaves exactly as it
// would in an IRC client talking to BouncerServ.
func splitWords(s string) ([]string, error) {
	var words []string
	var word strings.Builder
	escape := false
	delim := ' ' // ' ' while outside quotes, otherwise the closing quote
	prev := ' '

	for _, r := range s {
		switch {
		case escape:
			word.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case delim == ' ' && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			if prev != ' ' && prev != '\t' && prev != '\n' && prev != '\r' {
				words = append(words, word.String())
				word.Reset()
			}
		case r == delim:
			delim = ' '
		case r == '"' || r == '\'':
			if delim == ' ' {
				delim = r
			} else {
				word.WriteRune(r)
			}
		default:
			word.WriteRune(r)
		}
		prev = r
	}

	if prev != ' ' && prev != '\t' && prev != '\n' && prev != '\r' {
		words = append(words, word.String())
	}
	if delim != ' ' {
		return nil, errors.New("unterminated quoted string")
	}
	if escape {
		return nil, errors.New("unterminated backslash sequence")
	}
	return words, nil
}
