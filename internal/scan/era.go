package scan

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/NAMAN-VERMA-02/mcpfuzz/internal/rpc"
)

// serverInfo is what era detection learned.
type serverInfo struct {
	version      string
	tools        bool // the tools capability is advertised
	instructions string
}

var legacyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// detectEra follows the stdio binding of 2026-07-28: probe with server/discover;
// a DiscoverResult or a recognised modern error means modern, anything else
// (another error, silence) means legacy, so fall back to initialize. It returns
// nil when the era is unknown or unusable, after recording why.
func (s *session) detectEra() *serverInfo {
	m, err := s.c.Call("server/discover", map[string]any{"_meta": meta(modernVersion)}, s.opt.Timeout)
	if err == nil && m.Error == nil {
		var d struct {
			ResultType        *string                    `json:"resultType"`
			SupportedVersions []string                   `json:"supportedVersions"`
			Capabilities      map[string]json.RawMessage `json:"capabilities"`
			Instructions      string                     `json:"instructions"`
		}
		if json.Unmarshal(m.Result, &d) == nil && d.SupportedVersions != nil {
			s.era = "modern"
			if !slices.Contains(d.SupportedVersions, modernVersion) {
				s.add(Check{ID: "era", Status: Inconclusive,
					Detail: fmt.Sprintf("modern server does not support %s (supports %s); mcpfuzz speaks only that modern version", modernVersion, strings.Join(d.SupportedVersions, ", "))})
				return nil
			}
			var bad []string
			if d.ResultType == nil || *d.ResultType != "complete" {
				bad = append(bad, `resultType must be "complete"`)
			}
			if d.Capabilities == nil {
				bad = append(bad, "capabilities is missing")
			}
			s.judge(Check{ID: "modern.discover"}, bad, "server/discover returned a valid DiscoverResult", string(m.Raw))
			return &serverInfo{version: modernVersion, tools: d.Capabilities["tools"] != nil, instructions: d.Instructions}
		}
	}
	if err == nil && m.Error != nil && m.Error.Code == -32022 {
		s.era = "modern"
		s.add(Check{ID: "era", Status: Inconclusive,
			Detail: "modern server rejected " + modernVersion + " with UnsupportedProtocolVersion; mcpfuzz speaks only that modern version", Evidence: string(m.Error.Data)})
		return nil
	}

	// Legacy fallback. A server that died on the probe gets a fresh process.
	probe := "no answer"
	switch {
	case err != nil:
		probe = err.Error()
	case m.Error != nil:
		probe = fmt.Sprintf("error %d", m.Error.Code)
	default:
		probe = "a result that is not a DiscoverResult"
	}
	exited := err == rpc.ErrExited
	if !s.c.Alive() {
		s.close()
		if err := s.start(); err != nil {
			s.add(Check{ID: "era", Status: Inconclusive, Detail: "server/discover: " + probe + "; could not restart for initialize: " + err.Error()})
			return nil
		}
	}
	r, ierr := s.initialize()
	if ierr != nil {
		s.add(Check{ID: "era", Status: Inconclusive,
			Detail: fmt.Sprintf("neither era answered: server/discover gave %s, initialize gave %v", probe, ierr)})
		return nil
	}
	s.era = "legacy"
	if exited {
		s.add(Check{ID: "legacy.discover-probe", Status: Finding,
			Detail: "server exited when sent server/discover before initialize; it should return an error or ignore it"})
	}
	if !slices.Contains(legacyVersions, r.ProtocolVersion) {
		s.add(Check{ID: "era", Status: Inconclusive, Detail: fmt.Sprintf("initialize chose protocol version %q, which mcpfuzz does not speak", r.ProtocolVersion)})
		return nil
	}
	var bad []string
	if r.Capabilities == nil {
		bad = append(bad, "capabilities is missing")
	}
	if r.ServerInfo == nil || r.ServerInfo.Name == "" {
		bad = append(bad, "serverInfo.name is missing")
	}
	s.judge(Check{ID: "legacy.initialize"}, bad, "initialize returned version, capabilities and serverInfo", "")
	return &serverInfo{version: r.ProtocolVersion, tools: r.Capabilities["tools"] != nil, instructions: r.Instructions}
}

type initResult struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	ServerInfo      *struct {
		Name string `json:"name"`
	} `json:"serverInfo"`
	Instructions string `json:"instructions"`
}

// initialize runs the legacy handshake on the current process.
func (s *session) initialize() (*initResult, error) {
	m, err := s.c.Call("initialize", map[string]any{
		"protocolVersion": legacyVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcpfuzz", "version": Version},
	}, s.opt.Timeout)
	if err != nil {
		return nil, err
	}
	if m.Error != nil {
		return nil, fmt.Errorf("error %d: %s", m.Error.Code, m.Error.Message)
	}
	var r initResult
	if err := json.Unmarshal(m.Result, &r); err != nil {
		return nil, fmt.Errorf("result is not an InitializeResult: %v", err)
	}
	return &r, s.c.Notify("notifications/initialized", map[string]any{})
}

// judge records a check as FINDING when bad is non-empty, PASS otherwise.
func (s *session) judge(c Check, bad []string, ok, evidence string) {
	if len(bad) > 0 {
		c.Status, c.Detail, c.Evidence = Finding, strings.Join(bad, "; "), evidence
	} else {
		c.Status, c.Detail = Pass, ok
	}
	s.add(c)
}

// conformance runs the checks specific to the detected era. It returns whether
// the server offers tools; without them no tool check can pass.
func (s *session) conformance(info *serverInfo) bool {
	if s.era == "modern" {
		s.missingMeta()
		s.unsupportedVersion()
	} else {
		m, err := s.call("ping", nil)
		c := Check{ID: "legacy.ping"}
		if s.transport(c, "ping", m, err) {
			var obj map[string]any
			var bad []string
			if m.Error != nil || json.Unmarshal(m.Result, &obj) != nil {
				bad = []string{"ping must return an empty result object"}
			}
			s.judge(c, bad, "ping answered", string(m.Raw))
		}
	}
	s.wantError(Check{ID: "unknown-method"}, "an unknown method", "mcpfuzz/no-such-method", s.withMeta(nil), -32601)
	if !info.tools {
		s.add(Check{ID: "tools.list", Status: Inconclusive, Detail: "the server does not advertise the tools capability, so no tool check can run"})
		return false
	}
	return true
}

// withMeta adds the era's per-request fields to params.
func (s *session) withMeta(params map[string]any) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	if s.era == "modern" {
		params["_meta"] = meta(modernVersion)
	}
	return params
}

// missingMeta: a modern request without a required _meta field is malformed and
// must be rejected with -32602.
func (s *session) missingMeta() {
	noCaps := meta(modernVersion)
	delete(noCaps, "io.modelcontextprotocol/clientCapabilities")
	noVersion := meta(modernVersion)
	delete(noVersion, "io.modelcontextprotocol/protocolVersion")
	s.wantError(Check{ID: "modern.missing-meta"}, "tools/list with no _meta", "tools/list", map[string]any{}, -32602)
	s.wantError(Check{ID: "modern.missing-meta"}, "tools/list without clientCapabilities", "tools/list", map[string]any{"_meta": noCaps}, -32602)
	s.wantError(Check{ID: "modern.missing-meta"}, "tools/list without protocolVersion", "tools/list", map[string]any{"_meta": noVersion}, -32602)
}

// unsupportedVersion: an unknown version must get UnsupportedProtocolVersionError
// (-32022) listing the supported versions.
func (s *session) unsupportedVersion() {
	old := meta("1900-01-01")
	m := s.wantError(Check{ID: "modern.unsupported-version"}, "tools/list with protocol version 1900-01-01", "tools/list", map[string]any{"_meta": old}, -32022)
	if m == nil {
		return
	}
	var d struct {
		Supported []string `json:"supported"`
	}
	last := &s.checks[len(s.checks)-1]
	if json.Unmarshal(m.Error.Data, &d) != nil || d.Supported == nil {
		last.Status, last.Detail, last.Evidence = Finding, "UnsupportedProtocolVersionError must list supported versions in data.supported", clean(string(m.Raw), 200)
	}
}

// wantError sends a request that must be refused with code. It records a check
// and returns the response when the code matched.
func (s *session) wantError(c Check, what, method string, params map[string]any, code int) *rpc.Message {
	if err := s.ensure(); err != nil {
		s.add(Check{ID: c.ID, Status: Inconclusive, Detail: what + ": could not restart the server: " + err.Error()})
		return nil
	}
	m, err := s.raw(method, params)
	if !s.transport(c, what, m, err) {
		return nil
	}
	switch {
	case m.Error == nil:
		s.judge(c, []string{fmt.Sprintf("%s: accepted, want error %d", what, code)}, "", string(m.Raw))
	case m.Error.Code != code:
		s.judge(c, []string{fmt.Sprintf("%s: error %d, want %d", what, m.Error.Code, code)}, "", string(m.Raw))
	default:
		s.judge(c, nil, fmt.Sprintf("%s: rejected with %d", what, code), "")
		return m
	}
	return nil
}
