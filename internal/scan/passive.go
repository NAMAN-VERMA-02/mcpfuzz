package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
)

type tool struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations"`
	raw         json.RawMessage
}

const maxPages = 100

// listTools reads every page of tools/list.
func (s *session) listTools() []tool {
	var all []tool
	seen := map[string]bool{}
	var bad []string
	cursor := ""
	pages := 0
	for {
		if pages == maxPages {
			s.add(Check{ID: "tools.list", Status: Inconclusive, Detail: fmt.Sprintf("stopped after %d pages", maxPages)})
			return all
		}
		pages++
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		what := fmt.Sprintf("tools/list page %d", pages)
		m, err := s.call("tools/list", params)
		if !s.transport(Check{ID: "tools.list"}, what, m, err) {
			return all
		}
		if m.Error != nil {
			s.judge(Check{ID: "tools.list"}, []string{fmt.Sprintf("%s: error %d", what, m.Error.Code)}, "", string(m.Raw))
			return all
		}
		var r struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
			ResultType *string           `json:"resultType"`
			TTL        *int64            `json:"ttlMs"`
			CacheScope *string           `json:"cacheScope"`
		}
		if json.Unmarshal(m.Result, &r) != nil || r.Tools == nil {
			s.judge(Check{ID: "tools.list"}, []string{what + ": result needs a tools array and a string nextCursor"}, "", string(m.Raw))
			return all
		}
		if s.era == "modern" {
			if r.ResultType == nil || *r.ResultType != "complete" {
				bad = append(bad, what+`: resultType must be "complete"`)
			}
			if r.TTL == nil || *r.TTL < 0 {
				bad = append(bad, what+": ttlMs must be a non-negative integer")
			}
			if r.CacheScope == nil || (*r.CacheScope != "public" && *r.CacheScope != "private") {
				bad = append(bad, what+`: cacheScope must be "public" or "private"`)
			}
		}
		for _, raw := range r.Tools {
			var t tool
			if json.Unmarshal(raw, &t) != nil || t.Name == "" {
				bad = append(bad, what+": a tool has no name")
				continue
			}
			t.raw = raw
			all = append(all, t)
		}
		if r.NextCursor == "" {
			break
		}
		if seen[r.NextCursor] {
			bad = append(bad, fmt.Sprintf("%s: cursor %q was already returned, so paging never ends", what, r.NextCursor))
			break
		}
		seen[r.NextCursor] = true
		cursor = r.NextCursor
	}
	s.judge(Check{ID: "tools.list"}, bad, fmt.Sprintf("%d tools over %d page(s)", len(all), pages), "")
	return all
}

// analyze checks schemas and descriptions. Wording and annotations can only make
// a tool SUSPICIOUS: neither is evidence of what the tool does.
func (s *session) analyze(tools []tool, instructions string) []ToolInfo {
	for _, why := range injection([]string{instructions}) {
		s.add(Check{ID: "prompt-injection", Status: Suspicious, Tool: "(server instructions)", Detail: why.reason, Evidence: why.text})
	}
	infos := []ToolInfo{}
	for _, t := range tools {
		info := ToolInfo{Name: clean(t.Name, 80), ClaimedAnnotations: t.Annotations}

		var bad []string
		var schema map[string]any
		if json.Unmarshal(t.InputSchema, &schema) != nil || schema == nil {
			bad = append(bad, "inputSchema must be a JSON Schema object")
		} else if typ, ok := schema["type"]; (s.era == "legacy" || ok) && typ != "object" {
			bad = append(bad, `inputSchema must have "type": "object"`)
		}
		s.judge(Check{ID: "tools.schema", Tool: t.Name}, bad, "inputSchema is an object schema", string(t.InputSchema))

		var v any
		_ = json.Unmarshal(t.raw, &v)
		for _, why := range injection(strs(v, nil)) {
			s.add(Check{ID: "prompt-injection", Status: Suspicious, Tool: t.Name, Detail: why.reason, Evidence: why.text})
		}
		if why := annotationClash(t); why != "" {
			s.add(Check{ID: "annotations", Status: Suspicious, Tool: t.Name, Detail: why, Evidence: string(t.Annotations)})
		}
		props, _ := params(t.InputSchema)
		for _, name := range sortedKeys(props) {
			if kind := risky(name, props[name]); kind != "" {
				info.RiskyParams = append(info.RiskyParams, clean(name, 80)+" ("+kind+")")
			}
		}
		infos = append(infos, info)
	}
	return infos
}

type reason struct{ reason, text string }

var injectionRules = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`(?i)\bignore\b.{0,30}\b(previous|prior|above|earlier|all|other|any)\b.{0,20}\b(instructions?|rules|prompts?|directions)\b`), "asks the model to ignore its instructions"},
	{regexp.MustCompile(`(?i)\b(do not|don't|dont|never)\b.{0,20}\b(tell|inform|mention|reveal|show|alert|notify)\b.{0,20}\buser`), "asks the model to hide something from the user"},
	{regexp.MustCompile(`(?i)\bwithout\b.{0,15}\b(telling|informing|asking|notifying|alerting)\b.{0,15}\buser`), "asks the model to act without the user knowing"},
	{regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret|admin)\s*>`), "contains a pseudo-tag addressed to the model"},
	{regexp.MustCompile(`(?i)(~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.env\b|/etc/passwd|/etc/shadow|private key)`), "mentions secret files or keys"},
	{regexp.MustCompile(`(?i)\b(system prompt|developer message|previous conversation)\b`), "refers to the model's own context"},
}

// injection returns prompt-injection wording found in texts.
func injection(texts []string) []reason {
	var out []reason
	seen := map[string]bool{}
	for _, t := range texts {
		for _, r := range injectionRules {
			if loc := r.re.FindStringIndex(t); loc != nil && !seen[r.why] {
				seen[r.why] = true
				out = append(out, reason{r.why, around(t, loc[0], loc[1])})
			}
		}
		if i := strings.IndexFunc(t, func(r rune) bool { return unicode.Is(unicode.Cf, r) }); i >= 0 && !seen["hidden"] {
			seen["hidden"] = true
			out = append(out, reason{"contains invisible format characters (zero-width, bidi or tag characters) that can hide text from a human reviewer", around(t, i, i+1)})
		}
	}
	return out
}

func around(s string, i, j int) string {
	i, j = max(0, i-30), min(len(s), j+30)
	return s[i:j]
}

// strs collects every string value in a decoded JSON value.
func strs(v any, out []string) []string {
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, e := range x {
			out = strs(e, out)
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			out = strs(x[k], out)
		}
	}
	return out
}

var stateWords = []string{"write", "delete", "remove", "rm", "exec", "execute", "run", "shell", "command", "cmd",
	"kill", "create", "update", "add", "set", "put", "post", "send", "move", "drop", "install", "insert", "save"}

// annotationClash flags a tool that claims to be read-only while its name says it changes state.
func annotationClash(t tool) string {
	var a struct {
		ReadOnly *bool `json:"readOnlyHint"`
	}
	if json.Unmarshal(t.Annotations, &a) != nil || a.ReadOnly == nil || !*a.ReadOnly {
		return ""
	}
	for _, w := range words(t.Name) {
		if slices.Contains(stateWords, w) {
			return fmt.Sprintf("claims readOnlyHint, but its name (%q) says it changes state; annotations are self-reported and mcpfuzz never relies on them", w)
		}
	}
	return ""
}

// words splits snake_case, kebab-case and camelCase names into lower-case words.
func words(name string) []string {
	var out []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

var (
	pathWords    = []string{"path", "file", "filename", "dir", "directory", "folder", "root", "uri", "url"}
	commandWords = []string{"cmd", "command", "shell", "exec", "script", "args", "argv", "host", "hostname", "query", "expression"}
)

// risky names string parameters that look like paths or commands and have no
// constraint (enum, const, pattern). They are hints for --allow-tools, not findings.
func risky(name string, p map[string]any) string {
	if typeOf(p) != "string" || p["enum"] != nil || p["const"] != nil || p["pattern"] != nil {
		return ""
	}
	for _, w := range words(name) {
		if slices.Contains(pathWords, w) {
			return "path-like, unconstrained"
		}
		if slices.Contains(commandWords, w) {
			return "command-like, unconstrained"
		}
	}
	return ""
}

// params returns the top-level properties of an object schema and its required list.
func params(schema json.RawMessage) (map[string]map[string]any, []string) {
	var s struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	_ = json.Unmarshal(schema, &s)
	return s.Properties, s.Required
}

// typeOf returns a property's JSON type, the first non-null one if it lists several.
func typeOf(p map[string]any) string {
	switch t := p["type"].(type) {
	case string:
		return t
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "null" {
				return s
			}
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
