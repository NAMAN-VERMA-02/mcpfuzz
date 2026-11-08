//go:build !windows

package rpc

import (
	"os"
	"os/exec"
	"syscall"
)

// setGroup puts the server in its own process group so the whole tree can be killed.
func setGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killTree(p *os.Process) {
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
