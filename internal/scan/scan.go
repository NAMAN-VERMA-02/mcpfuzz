// Package scan checks an MCP server over stdio for spec-conformance bugs and
// security problems. It trusts nothing the server says about itself: a check
// passes only when the server's observed behaviour shows it.
package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/NAMAN-VERMA-02/mcpfuzz/internal/rpc"
)

// Version is reported to servers as clientInfo and written into reports.
const Version = "0.1.0"

// Status is the outcome of one check.
type Status string

const (
	Pass         Status = "PASS"         // the behaviour was observed and is correct
	Finding      Status = "FINDING"      // a problem was observed directly or confirmed by a canary
	Suspicious   Status = "SUSPICIOUS"   // worth a human look; never changes the verdict
	Inconclusive Status = "INCONCLUSIVE" // the check could not run safely or reliably
)

// Verdicts and their exit codes.
const (
	VerdictPass         = "PASS"
	VerdictFindings     = "FINDINGS"
	VerdictInconclusive = "INCONCLUSIVE"
	VerdictCouldNotRun  = "COULD_NOT_RUN"
)

// Check is one observation.
type Check struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	Tool     string `json:"tool,omitempty"`
	Param    string `json:"param,omitempty"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence,omitempty"`
}

// ToolInfo is what the server claimed about a tool. None of it is trusted.
type ToolInfo struct {
	Name               string          `json:"name"`
	ClaimedAnnotations json.RawMessage `json:"claimed_annotations,omitempty"`
	RiskyParams        []string        `json:"risky_params,omitempty"`
}

// Report is the result of a scan.
type Report struct {
	Verdict         string     `json:"verdict"`
	ExitCode        int        `json:"exit_code"`
	Era             string     `json:"era,omitempty"`
	ProtocolVersion string     `json:"protocol_version,omitempty"`
	Mode            string     `json:"mode"`
	Isolated        bool       `json:"isolated"`
	Target          []string   `json:"target"`
	Tools           []ToolInfo `json:"tools"`
	Checks          []Check    `json:"checks"`
	ServerStderr    string     `json:"server_stderr,omitempty"`
	Scanner         string     `json:"scanner"`
	Started         time.Time  `json:"started"`
	Seconds         float64    `json:"seconds"`
}

// Sandbox describes an isolated target. Paths are as the server sees them,
// except HostMarkerDir, which is the marker directory on this machine.
type Sandbox struct {
	AllowedRoot   string
	Canary        string // a file outside AllowedRoot
	CanaryValue   string // its random contents
	MarkerDir     string // injected commands try to create files here
	HostMarkerDir string
}

// Target is a server to scan.
type Target struct {
	Display []string
	// Command returns the argv for a fresh server process and a cleanup for it.
	// It is called again whenever the server has to be restarted.
	Command func() (argv []string, cleanup func())
	// Sandbox is nil when the server is not isolated; active probes then refuse to run.
	Sandbox *Sandbox
}

// Options select what to run.
type Options struct {
	Active     bool
	AllowTools []string
	Timeout    time.Duration // per call
}

// ErrCouldNotRun means the server could not be started at all.
var ErrCouldNotRun = errors.New("could not start the server")

const (
	modernVersion = "2026-07-28"
	legacyVersion = "2025-11-25"
)

type session struct {
	t      Target
	opt    Options
	era    string // "legacy" or "modern" once detected
	c      *rpc.Client
	checks []Check
	stderr string
	junk   int
	junk1  string
}

// Run scans the target. The only error it returns is ErrCouldNotRun.
func Run(t Target, opt Options) (*Report, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	start := time.Now()
	s := &session{t: t, opt: opt}
	if err := s.start(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCouldNotRun, err)
	}
	defer s.close()

	rep := &Report{Target: t.Display, Mode: "passive", Isolated: t.Sandbox != nil,
		Scanner: "mcpfuzz " + Version, Started: start.UTC(), Tools: []ToolInfo{}}
	if opt.Active {
		rep.Mode = "active"
	}
	if info := s.detectEra(); info != nil {
		rep.Era, rep.ProtocolVersion = s.era, info.version
		if s.conformance(info) {
			tools := s.listTools()
			rep.Tools = s.analyze(tools, info.instructions)
			if opt.Active {
				s.active(tools)
			}
		} else if opt.Active {
			s.add(Check{ID: "active", Status: Inconclusive, Detail: "active probes not run: the server offers no tools to probe"})
		}
	}
	s.close()
	if s.junk > 0 {
		s.add(Check{ID: "stdio.output", Status: Finding,
			Detail:   fmt.Sprintf("server wrote %d non-JSON line(s) to stdout; stdio servers must write only MCP messages there", s.junk),
			Evidence: s.junk1})
	}
	rep.Checks = s.checks
	rep.ServerStderr = clean(s.stderr, 2000)
	rep.Verdict, rep.ExitCode = verdict(s.checks)
	rep.Seconds = time.Since(start).Seconds()
	return rep, nil
}

// verdict: a confirmed finding outranks everything, because it stays true even
// when other probes could not run. Otherwise anything unrun keeps it from passing.
func verdict(cs []Check) (string, int) {
	inconclusive := len(cs) == 0
	for _, c := range cs {
		if c.Status == Finding {
			return VerdictFindings, 1
		}
		if c.Status == Inconclusive {
			inconclusive = true
		}
	}
	if inconclusive {
		return VerdictInconclusive, 2
	}
	return VerdictPass, 0
}

func (s *session) add(c Check) {
	c.Tool, c.Param = clean(c.Tool, 80), clean(c.Param, 80)
	c.Detail = clean(c.Detail, 400)
	c.Evidence = clean(c.Evidence, 200)
	s.checks = append(s.checks, c)
}

func (s *session) start() error {
	argv, cleanup := s.t.Command()
	c, err := rpc.Start(argv, cleanup)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return err
	}
	s.c = c
	return nil
}

func (s *session) close() {
	if s.c == nil {
		return
	}
	s.c.Close()
	n, first := s.c.Junk()
	if s.junk == 0 {
		s.junk1 = first
	}
	s.junk += n
	if e := s.c.Stderr(); e != "" {
		s.stderr = e
	}
	s.c = nil
}

// ensure restarts the server if it died or was killed after a hang.
func (s *session) ensure() error {
	if s.c != nil && s.c.Alive() {
		return nil
	}
	s.close()
	if err := s.start(); err != nil {
		return err
	}
	if s.era == "legacy" {
		if _, err := s.initialize(); err != nil {
			return fmt.Errorf("re-initializing after restart: %v", err)
		}
	}
	return nil
}

// meta is the per-request _meta every modern request must carry.
func meta(version string) map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    version,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "mcpfuzz", "version": Version},
	}
}

// call sends a request in the detected era, adding _meta when modern.
func (s *session) call(method string, params map[string]any) (*rpc.Message, error) {
	if err := s.ensure(); err != nil {
		return nil, fmt.Errorf("%w: %v", errRestart, err)
	}
	return s.raw(method, s.withMeta(params))
}

var errRestart = errors.New("could not restart the server")

func (s *session) raw(method string, params any) (*rpc.Message, error) {
	m, err := s.c.Call(method, params, s.opt.Timeout)
	if err == rpc.ErrTimeout {
		s.close() // a hung server may answer late; start clean next time
	}
	return m, err
}

// transport turns a failed call into a check. It returns false when there is
// no usable response; the caller should then stop judging this call.
func (s *session) transport(c Check, what string, m *rpc.Message, err error) bool {
	if err == nil {
		return true
	}
	c.Status = Finding
	switch {
	case errors.Is(err, errRestart):
		c.Status, c.Detail = Inconclusive, what+": "+err.Error()
	case err == rpc.ErrTimeout:
		c.Detail = fmt.Sprintf("%s: no response within %s (hang)", what, s.opt.Timeout)
	case err == rpc.ErrExited:
		s.close()
		c.Detail = fmt.Sprintf("%s: server exited (crash)", what)
		c.Evidence = crashLine(s.stderr)
	case err == rpc.ErrWrongID:
		c.Detail = fmt.Sprintf("%s: response id %s does not match the request", what, m.ID)
		c.Evidence = string(m.Raw)
	case err == rpc.ErrMalformed:
		c.Detail = what + `: response needs "jsonrpc":"2.0" and exactly one of result or error`
		c.Evidence = string(m.Raw)
	case err == rpc.ErrTooLarge:
		c.Status, c.Detail = Inconclusive, fmt.Sprintf("%s: message over the %d-byte limit, not judged", what, rpc.MaxMessage)
		s.close()
	default:
		c.Status, c.Detail = Inconclusive, what+": "+err.Error()
	}
	s.add(c)
	return false
}

// crashLine picks the most telling line of a dead server's stderr.
func crashLine(stderr string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "panic:") || strings.HasPrefix(l, "fatal error:") || strings.HasPrefix(l, "Traceback") {
			return l
		}
	}
	return lines[len(lines)-1]
}

// clean makes server-controlled text safe for a terminal and a report:
// control and invisible format characters become visible escapes.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		if r == '�' || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			if r == '\n' || r == '\t' {
				b.WriteByte(' ')
			} else {
				fmt.Fprintf(&b, `\u{%04X}`, r)
			}
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}
