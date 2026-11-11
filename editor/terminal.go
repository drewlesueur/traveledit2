package editor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type terminalRun struct {
	pty     *os.File
	stop    func()
	done    chan struct{}
	writeMu sync.Mutex
	buffer  []byte // protected by Handler.mu
	closed  bool
}

func (h *Handler) terminal(w http.ResponseWriter, r *http.Request, route string) {
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if route == "/myterminalpoll" {
		h.pollTerminals(w, r)
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "Editor closed", 503)
		return
	}
	if h.terminals == nil {
		h.terminals = map[int]*terminalRun{}
	}
	f := h.file(id)
	if route == "/myterminalsend" {
		run := h.terminals[id]
		if f == nil || f.Type != "terminal" || run == nil || run.closed {
			h.mu.Unlock()
			http.Error(w, "Terminal not found", 404)
			return
		}
		h.mu.Unlock()
		payload := r.FormValue("payload")
		if len(payload) > 65536 {
			http.Error(w, "Terminal input too large", 413)
			return
		}
		run.writeMu.Lock()
		_ = run.pty.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := run.pty.Write([]byte(payload))
		run.writeMu.Unlock()
		if err != nil {
			http.Error(w, "Terminal input failed", 500)
			return
		}
		w.WriteHeader(200)
		return
	}
	fresh := id == 0
	if !fresh && (f == nil || f.Type != "terminal") {
		h.mu.Unlock()
		http.Error(w, "Terminal not found", 404)
		return
	}
	if !fresh && h.terminals[id] != nil {
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]int{"ID": id})
		return
	}
	cwd := r.FormValue("cwd")
	if !fresh {
		cwd = f.CWD
	}
	if cwd == "" || cwd == "undefined" || cwd == "null" {
		cwd = h.config.Directory
	}
	cwd = h.fullPath(cwd)
	info, err := os.Stat(cwd)
	if err != nil || !info.IsDir() {
		h.mu.Unlock()
		http.Error(w, "Working directory unavailable", 400)
		return
	}
	pty, wait, stop, err := startTerminal(cwd)
	if err != nil {
		h.mu.Unlock()
		http.Error(w, fmt.Sprintf("Start terminal: %v", err), 500)
		return
	}
	run := &terminalRun{pty: pty, stop: stop, done: make(chan struct{})}
	if fresh {
		h.nextID++
		id = h.nextID
		f = &File{ID: id, Type: "terminal", FullPath: h.config.MountPath + "/terminal", CWD: cwd}
		ws := h.workspaces[h.current]
		ws.Files = append(ws.Files, f)
		if err = h.save(); err != nil {
			ws.Files = ws.Files[:len(ws.Files)-1]
			stop()
			h.mu.Unlock()
			wait()
			http.Error(w, "Could not save terminal", 500)
			return
		}
	}
	h.terminals[id] = run
	h.mu.Unlock()
	go func() {
		defer close(run.done)
		buf := make([]byte, 8192)
		for {
			n, err := pty.Read(buf)
			h.mu.Lock()
			if n > 0 {
				run.buffer = append(run.buffer, buf[:n]...)
				if len(run.buffer) > 1024*1024 {
					run.buffer = append([]byte(nil), run.buffer[len(run.buffer)-1024*1024:]...)
				}
			}
			h.mu.Unlock()
			if err != nil {
				break
			}
		}
		stop()
		wait()
		h.mu.Lock()
		run.closed = true
		h.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"ID": id})
}

func (h *Handler) pollTerminals(w http.ResponseWriter, r *http.Request) {
	ids := map[int]bool{}
	for _, value := range strings.Split(r.FormValue("ids"), ",") {
		id, _ := strconv.Atoi(value)
		if id > 0 {
			ids[id] = true
		}
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			http.Error(w, "Editor closed", 503)
			return
		}
		files := map[int]any{}
		for _, f := range h.workspaces[h.current].Files {
			if len(ids) > 0 && !ids[f.ID] {
				continue
			}
			run := h.terminals[f.ID]
			if run != nil && (len(run.buffer) > 0 || run.closed) {
				files[f.ID] = map[string]any{"Base64": base64.StdEncoding.EncodeToString(run.buffer), "Closed": run.closed}
				run.buffer = nil
			}
		}
		h.mu.Unlock()
		if len(files) > 0 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"Files": files})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Files":{}}`))
			return
		case <-tick.C:
		}
	}
}
