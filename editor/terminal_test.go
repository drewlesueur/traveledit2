//go:build linux

package editor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func terminalRequest(h *Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}
func terminalOpen(t *testing.T, h *Handler, id int) int {
	t.Helper()
	w := terminalRequest(h, fmt.Sprintf("/myterminalopen?id=%d", id))
	if w.Code != 200 {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	var result struct{ ID int }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.ID
}
func terminalOutput(t *testing.T, h *Handler, id int, needle string) string {
	t.Helper()
	output := ""
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", fmt.Sprintf("/myterminalpoll?ids=%d", id), nil).WithContext(ctx)
		h.ServeHTTP(w, r)
		var v struct {
			Files map[int]struct {
				Base64 string
				Closed bool
			}
		}
		if w.Body.Len() == 0 {
			break
		}
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.DecodeString(v.Files[id].Base64)
		if err != nil {
			t.Fatal(err)
		}
		output += string(data)
		if strings.Contains(output, needle) {
			return output
		}
	}
	t.Fatalf("output missing %q: %q", needle, output)
	return ""
}
func TestTerminalLifecycle(t *testing.T) {
	dir := t.TempDir()
	config := Config{EnableEditor: true, Directory: dir, StateFile: filepath.Join(dir, "state.json")}
	h, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	id := terminalOpen(t, h, 0)
	run := h.terminals[id]
	// Literal marker must be assembled by Bash, not just echoed input.
	command := "printf 'terminal-%s\\n' ready\n"
	w := terminalRequest(h, fmt.Sprintf("/myterminalsend?id=%d&payload=%s", id, url.QueryEscape(command)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	terminalOutput(t, h, id, "terminal-ready")
	if got := terminalOpen(t, h, id); got != id || h.terminals[id] != run {
		t.Fatal("reload started a second process")
	}
	other, _ := New(Config{EnableEditor: true, Directory: dir})
	defer other.Close()
	if w := terminalRequest(other, fmt.Sprintf("/myterminalsend?id=%d&payload=x", id)); w.Code != 404 {
		t.Fatal("cross-handler terminal access")
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-run.done:
	default:
		t.Fatal("terminal not reaped")
	}
	restored, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if len(restored.terminals) != 0 {
		t.Fatal("constructor spawned a terminal")
	}
	terminalOpen(t, restored, id)
	w = terminalRequest(restored, fmt.Sprintf("/myclose?id=%d", id))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if restored.file(id) != nil || restored.terminals[id] != nil {
		t.Fatal("closed terminal retained")
	}
}
func TestTerminalStartupFailureAndPollingCancellation(t *testing.T) {
	h, _ := New(Config{EnableEditor: true, Directory: t.TempDir()})
	defer h.Close()
	if w := terminalRequest(h, "/myterminalopen?cwd=/does-not-exist"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if len(h.terminals) != 0 {
		t.Fatal("failed start retained process")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/myterminalpoll", nil).WithContext(ctx))
	disabled, _ := New(Config{})
	defer disabled.Close()
	if w := terminalRequest(disabled, "/myterminalopen"); w.Code != 403 {
		t.Fatal("terminal available without EnableEditor", w.Code)
	}
}

func TestTerminalCloseKillsInteractiveJobs(t *testing.T) {
	dir := t.TempDir()
	h, _ := New(Config{EnableEditor: true, Directory: dir})
	defer h.Close()
	id := terminalOpen(t, h, 0)
	command := "sleep 30 & echo $! > child.pid\n"
	w := terminalRequest(h, fmt.Sprintf("/myterminalsend?id=%d&payload=%s", id, url.QueryEscape(command)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var pid int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(filepath.Join(dir, "child.pid"))
		pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
		if pid > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("child not started")
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		end := strings.LastIndexByte(string(data), ')')
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) > 0 && fields[0] != "Z" {
			t.Fatal("background terminal job survived shutdown")
		}
	}
}

func TestTerminalPersistenceFailures(t *testing.T) {
	dir := t.TempDir()
	h, _ := New(Config{EnableEditor: true, Directory: dir})
	defer h.Close()
	id := terminalOpen(t, h, 0)
	run := h.terminals[id]
	// Renaming a state file over a directory fails without changing the workspace.
	h.config.StateFile = dir
	if w := terminalRequest(h, fmt.Sprintf("/myclose?id=%d", id)); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if h.terminals[id] != run || h.file(id) == nil {
		t.Fatal("failed close lost running terminal")
	}
	select {
	case <-run.done:
		t.Fatal("failed save stopped terminal")
	default:
	}
	count := len(h.workspaces[h.current].Files)
	if w := terminalRequest(h, "/myterminalopen"); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if len(h.terminals) != 1 || len(h.workspaces[h.current].Files) != count {
		t.Fatal("failed open retained terminal")
	}
}
