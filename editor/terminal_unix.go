//go:build !windows

package editor

import (
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

func startTerminal(cwd string) (*os.File, func(), func(), error) {
	cmd := exec.Command("bash", "-l")
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		return nil, nil, nil, err
	}
	var once sync.Once
	stop := func() { once.Do(func() { killTerminalSession(cmd.Process.Pid); _ = f.Close() }) }
	return f, func() { _ = cmd.Wait() }, stop, nil
}

func killTerminalGroup(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
