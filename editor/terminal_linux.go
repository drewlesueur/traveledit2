package editor

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Interactive jobs have separate process groups but share the terminal session.
func killTerminalSession(pid int) {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		child, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 4 {
			continue
		}
		session, _ := strconv.Atoi(fields[3])
		if session == pid {
			_ = syscall.Kill(child, syscall.SIGKILL)
		}
	}
	killTerminalGroup(pid)
}
