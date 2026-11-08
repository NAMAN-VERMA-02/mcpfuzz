package scan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NAMAN-VERMA-02/mcpfuzz/internal/rpc"
)

const oversized = 512 << 10 // bytes in the oversized-argument probe; below rpc.MaxPayload

var shellTemplates = []string{
	"mcpfuzz; touch %s",
	"mcpfuzz | touch %s",
	"mcpfuzz && touch %s",
	"$(touch %s)",
	"`touch %s`",
	"mcpfuzz\ntouch %s",
}

// active calls only allow-listed tools, and only when the target is sandboxed.
// Tool annotations play no part: a tool that claims to be read-only is probed
// like any other once it is on the allowlist.
func (s *session) active(tools []tool) {
	sb := s.t.Sandbox
	if sb == nil {
		s.add(Check{ID: "active", Status: Inconclusive,
			Detail: "active probes refused: the target is not isolated. Give --image so the server runs in Docker with no network, a read-only root and no capabilities"})
		return
	}
	byName := map[string]tool{}
	for _, t := range tools {
		byName[t.Name] = t
	}
	nonce := randHex(6)
	for _, name := range s.opt.AllowTools {
		t, ok := byName[name]
		if !ok {
			s.add(Check{ID: "active.allowlist", Status: Inconclusive, Tool: name, Detail: "allow-listed tool is not offered by the server, so it was not probed"})
			continue
		}
		s.probeTool(t, sb, nonce)
	}
	s.unknownTool(nonce)
	s.invalidJSONRPC()
}

func (s *session) probeTool(t tool, sb *Sandbox, nonce string) {
	props, required := params(t.InputSchema)
	base := map[string]any{}
	for _, name := range required {
		base[name] = benign(props[name])
	}
	var strParams []string
	for _, name := range sortedKeys(props) {
		if typeOf(props[name]) == "string" {
			strParams = append(strParams, name)
		}
	}
	if len(strParams) == 0 {
		for _, id := range []string{"active.path-traversal", "active.shell-injection"} {
			s.add(Check{ID: id, Status: Inconclusive, Tool: t.Name, Detail: "the tool has no string parameter to carry a payload"})
		}
	}

	for _, p := range strParams {
		s.traversal(t.Name, p, base, sb)
		s.shell(t.Name, p, base, sb, nonce)
		if _, ok := s.toolCall("active.oversized", t.Name, p, "a 512 KiB string", with(base, p, strings.Repeat("A", oversized))); ok {
			s.add(Check{ID: "active.oversized", Status: Pass, Tool: t.Name, Param: p, Detail: "answered a 512 KiB argument"})
		}
	}
	for _, p := range sortedKeys(props) {
		wrong, ok := wrongType(props[p])
		if !ok {
			continue
		}
		what := fmt.Sprintf("a %T where the schema says %s", wrong, typeOf(props[p]))
		if _, ok := s.toolCall("active.wrong-type", t.Name, p, what, with(base, p, wrong)); ok {
			s.add(Check{ID: "active.wrong-type", Status: Pass, Tool: t.Name, Param: p, Detail: "answered " + what})
		}
	}
}

// traversal is confirmed only when the canary's random contents, which sit
// outside the allowed root, come back in the tool's response.
func (s *session) traversal(name, p string, base map[string]any, sb *Sandbox) {
	c := Check{ID: "active.path-traversal", Tool: name, Param: p}
	missed := 0
	for _, payload := range traversalPayloads(sb) {
		m, ok := s.toolCall("active.robustness", name, p, fmt.Sprintf("traversal payload %q", payload), with(base, p, payload))
		if !ok {
			missed++
			continue
		}
		if strings.Contains(string(m.Raw), sb.CanaryValue) {
			c.Status, c.Evidence = Finding, "payload "+payload
			c.Detail = "the contents of a canary file outside --allowed-root appeared in the tool's output"
			s.add(c)
			return
		}
	}
	if missed > 0 {
		c.Status, c.Detail = Inconclusive, fmt.Sprintf("%d traversal payload(s) got no usable response, so the canary could not be looked for", missed)
	} else {
		c.Status, c.Detail = Pass, "no traversal payload brought back the canary"
	}
	s.add(c)
}

func traversalPayloads(sb *Sandbox) []string {
	abs := filepath.ToSlash(sb.Canary)
	var out []string
	if rel, err := filepath.Rel(sb.AllowedRoot, sb.Canary); err == nil {
		rel = filepath.ToSlash(rel)
		out = append(out, rel, strings.ReplaceAll(rel, "/", "%2f"))
	}
	return append(out, abs, strings.Repeat("../", 16)+strings.TrimLeft(abs, "/"))
}

// shell is confirmed only when an injected command creates its marker file.
func (s *session) shell(name, p string, base map[string]any, sb *Sandbox, nonce string) {
	c := Check{ID: "active.shell-injection", Tool: name, Param: p}
	payloads := map[string]string{} // marker file -> payload
	missed := 0
	for i, tmpl := range shellTemplates {
		file := fmt.Sprintf("marker-%s-%s-%s-%d", nonce, safe(name), safe(p), i)
		payload := fmt.Sprintf(tmpl, "'"+filepath.ToSlash(filepath.Join(sb.MarkerDir, file))+"'")
		payloads[file] = payload
		if _, ok := s.toolCall("active.robustness", name, p, fmt.Sprintf("shell payload %q", payload), with(base, p, payload)); !ok {
			missed++
		}
	}
	time.Sleep(300 * time.Millisecond) // let a backgrounded injected command finish
	for _, file := range sortedKeys(payloads) {
		if _, err := os.Stat(filepath.Join(sb.HostMarkerDir, file)); err == nil {
			c.Status, c.Evidence = Finding, "payload "+payloads[file]
			c.Detail = "an injected shell command ran: it created a marker file"
			s.add(c)
			return
		}
	}
	if missed > 0 {
		c.Status, c.Detail = Inconclusive, fmt.Sprintf("%d shell payload(s) got no usable response", missed)
	} else {
		c.Status, c.Detail = Pass, "no shell payload created its marker file"
	}
	s.add(c)
}

// toolCall calls a tool. Crashes and hangs become findings under id.
func (s *session) toolCall(id, name, p, what string, args map[string]any) (*rpc.Message, bool) {
	m, err := s.call("tools/call", map[string]any{"name": name, "arguments": args})
	return m, s.transport(Check{ID: id, Tool: name, Param: p}, "sent "+what, m, err)
}

// unknownTool calls a tool name the server did not list. It must not report success.
func (s *session) unknownTool(nonce string) {
	name := "mcpfuzz_no_such_tool_" + nonce
	c := Check{ID: "active.unknown-tool"}
	m, err := s.call("tools/call", map[string]any{"name": name, "arguments": map[string]any{}})
	if !s.transport(c, "call to an unlisted tool", m, err) {
		return
	}
	var r struct {
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(m.Result, &r)
	var bad []string
	if m.Error == nil && !r.IsError {
		bad = []string{"reported success for a tool it does not list"}
	}
	s.judge(c, bad, "refused a tool it does not list", string(m.Raw))
}

// invalidJSONRPC sends malformed messages. The server may answer with an error or
// stay silent, but it must not crash, answer with a result, or stop answering.
func (s *session) invalidJSONRPC() {
	probes := []struct{ name, line string }{
		{"truncated JSON", `{"jsonrpc":"2.0","id":`},
		{"a method that is not a string", `{"jsonrpc":"2.0","id":"mcpfuzz-bad","method":7}`},
		{"an empty batch", `[]`},
	}
	liveness := "ping"
	if s.era == "modern" {
		liveness = "server/discover"
	}
	for _, p := range probes {
		c := Check{ID: "active.invalid-jsonrpc"}
		if err := s.ensure(); err != nil {
			c.Status, c.Detail = Inconclusive, p.name+": could not restart the server: "+err.Error()
			s.add(c)
			continue
		}
		m, err := s.c.SendRaw([]byte(p.line), min(2*time.Second, s.opt.Timeout))
		s.c.Ignore("null")
		s.c.Ignore(`"mcpfuzz-bad"`)
		switch {
		case err == rpc.ErrExited:
			s.close()
			c.Status, c.Detail, c.Evidence = Finding, p.name+": server exited (crash)", crashLine(s.stderr)
		case err == nil && m.Error == nil:
			c.Status, c.Detail, c.Evidence = Finding, p.name+": answered with a result instead of an error", string(m.Raw)
		case err == rpc.ErrTooLarge:
			c.Status, c.Detail = Inconclusive, p.name+": answer over the size limit"
		default:
			lm, lerr := s.raw(liveness, s.withMeta(nil))
			if lerr != nil || lm.Error != nil {
				c.Status, c.Detail = Finding, fmt.Sprintf("%s: the server stopped answering %s afterwards", p.name, liveness)
			} else {
				c.Status, c.Detail = Pass, p.name+": refused or ignored, and the server kept working"
			}
		}
		s.add(c)
	}
}

func with(base map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(base)+1)
	for bk, bv := range base {
		out[bk] = bv
	}
	out[k] = v
	return out
}

// benign is a harmless valid-looking value for a required parameter.
func benign(p map[string]any) any {
	if e, ok := p["enum"].([]any); ok && len(e) > 0 {
		return e[0]
	}
	switch typeOf(p) {
	case "integer", "number":
		return 1
	case "boolean":
		return false
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	}
	return "mcpfuzz"
}

func wrongType(p map[string]any) (any, bool) {
	switch typeOf(p) {
	case "":
		return nil, false
	case "string":
		return 12345, true
	}
	return "mcpfuzz", true
}

// safe makes a short file-name-safe label, so long tool names can't overflow a file name.
func safe(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
