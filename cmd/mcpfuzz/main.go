// Command mcpfuzz scans an MCP server over stdio for spec-conformance bugs and security problems.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NAMAN-VERMA-02/mcpfuzz/internal/rpc"
	"github.com/NAMAN-VERMA-02/mcpfuzz/internal/scan"
)

const usage = `mcpfuzz scans an MCP server over stdio for spec-conformance bugs and security problems.

Usage:
  mcpfuzz scan [flags] -- <server command...>

Passive (the default) detects the protocol era, checks conformance, lists every
tool and analyses schemas and descriptions. It calls no tools.

Active (--active) also sends attack payloads to allow-listed tools. It needs
--allow-tools, --allowed-root, --i-own-this-target and --image: the server must
run isolated in Docker, or the active part is INCONCLUSIVE.

Exit codes: 0 pass, 1 findings, 2 inconclusive, 3 could not run.
Only scan servers you own or are authorised to test.
`

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		if len(os.Args) >= 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
			fmt.Print(usage)
			return
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(3)
	}
	os.Exit(run(os.Args[2:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	active := fs.Bool("active", false, "send attack payloads to allow-listed tools (needs every flag below and --image)")
	allow := fs.String("allow-tools", "", "comma-separated tools that active probes may call")
	root := fs.String("allowed-root", "", "directory the server may touch, as the container sees it, e.g. /work")
	owner := fs.Bool("i-own-this-target", false, "confirm you own or are authorised to test this server")
	image := fs.String("image", "", "run the server command inside this local Docker image, isolated")
	jsonOut := fs.String("json", "", "write the JSON report to this file")
	timeout := fs.Duration("timeout", 10*time.Second, "deadline for each call")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	argv := fs.Args()
	fail := func(msg string) int {
		fmt.Fprintln(stderr, "mcpfuzz:", msg)
		return 3
	}
	if len(argv) == 0 {
		return fail("no server command; put it after --")
	}
	var tools []string
	for _, t := range strings.Split(*allow, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tools = append(tools, t)
		}
	}
	if *active {
		switch {
		case len(tools) == 0:
			return fail("--active needs --allow-tools: name every tool the probes may call")
		case *root == "":
			return fail("--active needs --allowed-root")
		case !*owner:
			return fail("--active needs --i-own-this-target: only probe servers you own or are authorised to test")
		}
	} else if len(tools) > 0 || *root != "" {
		return fail("--allow-tools and --allowed-root only apply with --active")
	}
	if *timeout <= 0 {
		return fail("--timeout must be positive")
	}

	target := scan.Target{Display: argv, Command: func() ([]string, func()) { return argv, nil }}
	if *image != "" {
		r := *root
		if r == "" {
			r = "/work" // passive scans still mount a scratch work directory
		}
		t, cleanup, err := scan.Docker(*image, r, argv)
		if err != nil {
			return fail(err.Error())
		}
		defer cleanup()
		target = t
		onInterrupt(cleanup)
	} else {
		onInterrupt(func() {})
	}

	rep, err := scan.Run(target, scan.Options{Active: *active, AllowTools: tools, Timeout: *timeout})
	if err != nil {
		return fail(err.Error())
	}
	summary(stdout, rep)
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			return fail("writing the report: " + err.Error())
		}
	}
	return rep.ExitCode
}

// onInterrupt kills every server process and removes temporary files on Ctrl-C.
func onInterrupt(cleanup func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		rpc.CloseAll()
		cleanup()
		os.Exit(3)
	}()
}

func summary(w io.Writer, r *scan.Report) {
	fmt.Fprintf(w, "mcpfuzz: %s (exit %d)\n", r.Verdict, r.ExitCode)
	era := "unknown"
	if r.Era != "" {
		era = r.Era + " (" + r.ProtocolVersion + ")"
	}
	iso := "not isolated"
	if r.Isolated {
		iso = "isolated in Docker"
	}
	fmt.Fprintf(w, "era: %s · %s scan · %s · %d tools\n\n", era, r.Mode, iso, len(r.Tools))
	passed := 0
	for _, c := range r.Checks {
		if c.Status == scan.Pass {
			passed++
			continue
		}
		where := c.Tool
		if c.Param != "" {
			where += "." + c.Param
		}
		if where != "" {
			where = " [" + where + "]"
		}
		fmt.Fprintf(w, "%-12s %s%s: %s\n", c.Status, c.ID, where, c.Detail)
		if c.Evidence != "" {
			fmt.Fprintf(w, "             evidence: %s\n", c.Evidence)
		}
	}
	fmt.Fprintf(w, "%-12s %d checks\n", "PASS", passed)
	for _, t := range r.Tools {
		if len(t.RiskyParams) > 0 {
			fmt.Fprintf(w, "hint         %s has %s\n", t.Name, strings.Join(t.RiskyParams, ", "))
		}
	}
	if r.Verdict == scan.VerdictInconclusive && r.ServerStderr != "" {
		fmt.Fprintf(w, "server stderr: %s\n", r.ServerStderr)
	}
}
