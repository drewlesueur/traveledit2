//go:build !linux && !windows

package editor

func killTerminalSession(pid int) { killTerminalGroup(pid) }
