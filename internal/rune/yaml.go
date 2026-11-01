package rune

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type yamlLine struct {
	indent int
	text   string
	num    int
}

// parseYAML handles the intentionally bounded YAML subset used by rune files.
// It supports mappings, sequences, scalar values and literal/folded blocks.
func parseYAML(src string) (map[string]any, error) {
	if len(src) > 512*1024 {
		return nil, errors.New("rune exceeds the 512 KiB size limit")
	}
	var lines []yamlLine
	s := bufio.NewScanner(strings.NewReader(src))
	s.Buffer(make([]byte, 4096), 1024*1024)
	for n := 1; s.Scan(); n++ {
		raw := strings.TrimRight(s.Text(), " \r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if strings.Contains(raw[:indent], "\t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed for indentation", n)
		}
		txt := stripComment(strings.TrimSpace(raw))
		if txt == "" || txt == "---" || txt == "..." {
			continue
		}
		lines = append(lines, yamlLine{indent, txt, n})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("rune file is empty")
	}
	if lines[0].indent != 0 {
		return nil, fmt.Errorf("line %d: top-level indentation is not allowed", lines[0].num)
	}
	idx := 0
	node, err := parseBlock(lines, &idx, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if idx != len(lines) {
		return nil, fmt.Errorf("line %d: unexpected content", lines[idx].num)
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil, errors.New("rune must be a mapping")
	}
	return m, nil
}
func stripComment(s string) string {
	quote := rune(0)
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quote == '"' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == '#' && (i == 0 || s[i-1] == ' ') {
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}
func parseBlock(ls []yamlLine, i *int, indent int) (any, error) {
	if *i >= len(ls) {
		return nil, nil
	}
	if strings.HasPrefix(ls[*i].text, "-") {
		return parseSeq(ls, i, indent)
	}
	return parseMap(ls, i, indent, nil)
}
func parseMap(ls []yamlLine, i *int, indent int, initial map[string]any) (map[string]any, error) {
	m := initial
	if m == nil {
		m = map[string]any{}
	}
	for *i < len(ls) {
		ln := ls[*i]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", ln.num)
		}
		if strings.HasPrefix(ln.text, "-") {
			break
		}
		key, val, ok := splitPair(ln.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected key: value", ln.num)
		}
		if _, exists := m[key]; exists {
			return nil, fmt.Errorf("line %d: duplicate key %q", ln.num, key)
		}
		*i++
		if val == "|" || val == ">" || val == "|-" || val == ">-" || val == "|+" || val == ">+" {
			var chunks []string
			blockIndent := -1
			for *i < len(ls) && ls[*i].indent > indent {
				cur := ls[*i]
				if blockIndent < 0 {
					blockIndent = cur.indent
				}
				if cur.indent < blockIndent {
					return nil, fmt.Errorf("line %d: inconsistent block indentation", cur.num)
				}
				chunks = append(chunks, strings.Repeat(" ", cur.indent-blockIndent)+cur.text)
				*i++
			}
			sep := "\n"
			if strings.HasPrefix(val, ">") {
				sep = " "
			}
			m[key] = strings.Join(chunks, sep)
			continue
		}
		if val != "" {
			v, e := scalar(val)
			if e != nil {
				return nil, fmt.Errorf("line %d: %w", ln.num, e)
			}
			m[key] = v
			continue
		}
		if *i < len(ls) && ls[*i].indent > indent {
			v, e := parseBlock(ls, i, ls[*i].indent)
			if e != nil {
				return nil, e
			}
			m[key] = v
		} else {
			m[key] = nil
		}
	}
	return m, nil
}
func parseSeq(ls []yamlLine, i *int, indent int) ([]any, error) {
	var out []any
	for *i < len(ls) {
		ln := ls[*i]
		if ln.indent < indent {
			break
		}
		if ln.indent != indent || !strings.HasPrefix(ln.text, "-") {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		*i++
		if rest == "" {
			if *i < len(ls) && ls[*i].indent > indent {
				v, e := parseBlock(ls, i, ls[*i].indent)
				if e != nil {
					return nil, e
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if key, val, ok := splitPair(rest); ok {
			m := map[string]any{}
			if val == "" {
				if *i < len(ls) && ls[*i].indent > indent+1 {
					v, e := parseBlock(ls, i, ls[*i].indent)
					if e != nil {
						return nil, e
					}
					m[key] = v
				} else {
					m[key] = nil
				}
			} else if val == "|" || val == ">" {
				var chunks []string
				blockIndent := -1
				for *i < len(ls) && ls[*i].indent > indent {
					cur := ls[*i]
					if blockIndent < 0 {
						blockIndent = cur.indent
					}
					chunks = append(chunks, strings.Repeat(" ", cur.indent-blockIndent)+cur.text)
					*i++
				}
				sep := "\n"
				if val == ">" {
					sep = " "
				}
				m[key] = strings.Join(chunks, sep)
			} else {
				v, e := scalar(val)
				if e != nil {
					return nil, fmt.Errorf("line %d: %w", ln.num, e)
				}
				m[key] = v
			}
			if *i < len(ls) && ls[*i].indent > indent {
				childIndent := ls[*i].indent
				if _, e := parseMap(ls, i, childIndent, m); e != nil {
					return nil, e
				}
			}
			out = append(out, m)
			continue
		}
		v, e := scalar(rest)
		if e != nil {
			return nil, fmt.Errorf("line %d: %w", ln.num, e)
		}
		if *i < len(ls) && ls[*i].indent > indent {
			return nil, fmt.Errorf("line %d: scalar list item cannot have children", ls[*i].num)
		}
		out = append(out, v)
	}
	return out, nil
}
func splitPair(s string) (string, string, bool) {
	quote := rune(0)
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quote == '"' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			return strings.Trim(strings.TrimSpace(s[:i]), "\"'"), strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}
func scalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inside := strings.TrimSpace(s[1 : len(s)-1])
		if inside == "" {
			return []any{}, nil
		}
		parts := splitInline(inside)
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			v, e := scalar(p)
			if e != nil {
				return nil, e
			}
			out = append(out, v)
		}
		return out, nil
	}
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		inside := strings.TrimSpace(s[1 : len(s)-1])
		out := map[string]any{}
		if inside == "" {
			return out, nil
		}
		for _, part := range splitInline(inside) {
			key, value, ok := splitPair(part)
			if !ok || key == "" {
				return nil, fmt.Errorf("invalid inline mapping entry %q", part)
			}
			if _, exists := out[key]; exists {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			parsed, err := scalar(value)
			if err != nil {
				return nil, err
			}
			out[key] = parsed
		}
		return out, nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		v, e := strconv.Unquote(s)
		return v, e
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	switch strings.ToLower(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null", "~":
		return nil, nil
	}
	if i, e := strconv.ParseInt(s, 10, 64); e == nil {
		return i, nil
	}
	if f, e := strconv.ParseFloat(s, 64); e == nil {
		return f, nil
	}
	return s, nil
}
func splitInline(s string) []string {
	var out []string
	start := 0
	quote := rune(0)
	depth := 0
	for i, r := range s {
		if quote != 0 {
			if r == quote && (i == 0 || s[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == '[' || r == '{' {
			depth++
		}
		if r == ']' || r == '}' {
			depth--
		}
		if r == ',' && depth == 0 {
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

func Decode(src string, dst any) error {
	m, e := parseYAML(src)
	if e != nil {
		return e
	}
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("rune fields: %w", err)
	}
	return nil
}
