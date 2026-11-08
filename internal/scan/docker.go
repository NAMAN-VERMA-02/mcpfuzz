package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Paths inside the container. The canary and marker directories sit outside any
// allowed root that validRoot accepts.
const (
	canaryDir = "/mcpfuzz-canary"
	markerDir = "/mcpfuzz-marker"
)

var rootRE = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)

// validRoot accepts an absolute container path that cannot contain the canary.
func validRoot(root string) error {
	if !rootRE.MatchString(root) || filepath.ToSlash(filepath.Clean(root)) != root {
		return fmt.Errorf("--allowed-root %q must be a clean absolute path inside the container, such as /work", root)
	}
	if strings.HasPrefix(root, "/mcpfuzz-") {
		return fmt.Errorf("--allowed-root %q collides with mcpfuzz's own mounts", root)
	}
	return nil
}

// Docker runs argv inside image, isolated: no network, a read-only root, every
// capability dropped, no privilege escalation, an unprivileged user, and bounded
// pids and memory. Three host directories are mounted: a fresh work directory at
// allowedRoot, a read-only canary outside it, and a marker directory. The
// returned cleanup removes them.
func Docker(image, allowedRoot string, argv []string) (Target, func(), error) {
	if err := validRoot(allowedRoot); err != nil {
		return Target{}, nil, err
	}
	if image == "" || strings.HasPrefix(image, "-") {
		return Target{}, nil, fmt.Errorf("invalid image %q", image)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		return Target{}, nil, fmt.Errorf("docker is not available: %v: %s", err, strings.TrimSpace(string(out)))
	}

	dir, err := os.MkdirTemp("", "mcpfuzz-")
	if err != nil {
		return Target{}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	work, canary, marker := filepath.Join(dir, "work"), filepath.Join(dir, "canary"), filepath.Join(dir, "marker")
	value := "MCPFUZZ-CANARY-" + randHex(16)
	err = firstErr(
		os.Mkdir(work, 0o755), os.Mkdir(canary, 0o755), os.Mkdir(marker, 0o755),
		// The container runs as nobody without capabilities, so it needs plain write permission.
		os.Chmod(work, 0o777), os.Chmod(marker, 0o777),
		os.WriteFile(filepath.Join(work, "hello.txt"), []byte("hello from mcpfuzz\n"), 0o644),
		os.WriteFile(filepath.Join(canary, "canary.txt"), []byte(value+"\n"), 0o644),
	)
	if err != nil {
		cleanup()
		return Target{}, nil, err
	}

	prefix, n := "mcpfuzz-"+randHex(4), 0
	t := Target{
		Display: append([]string{"docker:" + image}, argv...),
		Sandbox: &Sandbox{AllowedRoot: allowedRoot, Canary: canaryDir + "/canary.txt", CanaryValue: value,
			MarkerDir: markerDir, HostMarkerDir: marker},
		Command: func() ([]string, func()) {
			n++
			name := fmt.Sprintf("%s-%d", prefix, n)
			return dockerArgs(name, image, work, allowedRoot, canary, marker, argv), func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
			}
		},
	}
	return t, cleanup, nil
}

func dockerArgs(name, image, work, root, canary, marker string, argv []string) []string {
	args := []string{"docker", "run", "--rm", "-i", "--name", name, "--pull", "never",
		"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "65534:65534", "--pids-limit", "128", "--memory", "512m",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
		"--mount", "type=bind,source=" + work + ",target=" + root,
		"--mount", "type=bind,source=" + canary + ",target=" + canaryDir + ",readonly",
		"--mount", "type=bind,source=" + marker + ",target=" + markerDir,
		image}
	return append(args, argv...)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
