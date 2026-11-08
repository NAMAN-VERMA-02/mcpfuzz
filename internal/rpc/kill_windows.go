package rpc

import (
	"os"
	"os/exec"
	"strconv"
)

func setGroup(*exec.Cmd) {}

// killTree uses taskkill /T, which ends the process and every child it started.
func killTree(p *os.Process) {
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run()
	_ = p.Kill()
}
