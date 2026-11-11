package editor

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// File contents can be shared by otherwise independent per-user handlers.
// Serialize library writes across handlers as well as within each workspace.
var fileSaveMu sync.Mutex

type commandRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (h *Handler) validFile(f *File) bool {
	if validTab(f.Type, f.FullPath) {
		return true
	}
	return h.config.EnableEditor && (f.Type == "file" || f.Type == "directory" || f.Type == "shell" || f.Type == "iframe" || f.Type == "terminal")
}
func (h *Handler) file(id int) *File {
	for _, f := range h.workspaces[h.current].Files {
		if f.ID == id {
			return f
		}
	}
	return nil
}
func hash(data []byte) string { return fmt.Sprintf("%x", md5.Sum(data)) }
func (h *Handler) fullPath(raw string) string {
	// The client sends absolute paths after opening a directory. Relative names
	// start from the configured directory, as normal TravelEdit commands do.
	if !filepath.IsAbs(raw) {
		raw = filepath.Join(h.config.Directory, raw)
	}
	return filepath.Clean(raw)
}
func (h *Handler) serveEditor(w http.ResponseWriter, r *http.Request, route string) bool {
	switch route {
	case "/myterminalopen", "/myterminalsend", "/myterminalpoll":
		h.terminal(w, r, route)
		return true
	case "/myshell", "/myquickshell":
		h.shell(w, r, route == "/myquickshell")
		return true
	case "/saveload":
		h.saveLoad(w, r)
		return true
	case "/duplfile":
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			http.Error(w, "Editor closed", 503)
			return true
		}
		id, _ := strconv.Atoi(r.FormValue("idtodup"))
		f := h.file(id)
		if f == nil {
			http.Error(w, "Tab not found", 404)
			return true
		}
		clone := *f
		h.nextID++
		clone.ID = h.nextID
		h.workspaces[h.current].Files = append(h.workspaces[h.current].Files, &clone)
		if err := h.save(); err != nil {
			h.workspaces[h.current].Files = h.workspaces[h.current].Files[:len(h.workspaces[h.current].Files)-1]
			h.nextID--
			http.Error(w, "Could not save workspace", 500)
			return true
		}
		w.Header().Set("X-ID", strconv.Itoa(clone.ID))
		w.WriteHeader(200)
		return true
	}
	return false
}
func (h *Handler) shell(w http.ResponseWriter, r *http.Request, quick bool) {
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	cwd := r.FormValue("cwd")
	if cwd == "" || cwd == "undefined" || cwd == "null" {
		cwd = h.config.Directory
	}
	cwd = h.fullPath(cwd)
	info, err := os.Stat(cwd)
	if err != nil || !info.IsDir() {
		http.Error(w, "Working directory unavailable", 400)
		return
	}
	command := r.FormValue("cmd")
	if command == "" {
		command = ":"
	}
	if !quick {
		command += "\nprintf '\\n'; pwd"
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = cwd
	cmd.WaitDelay = time.Second
	configureCommand(cmd)
	run := &commandRun{cancel: cancel, done: make(chan struct{})}
	id, _ := strconv.Atoi(r.FormValue("id"))
	fresh := id == 0
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "Editor closed", 503)
		return
	}
	if h.runs == nil {
		h.runs = make(map[int]*commandRun)
	}
	var f *File
	if !quick {
		if fresh {
			h.nextID++
			id = h.nextID
			f = &File{ID: id, Type: "shell", FullPath: h.config.MountPath + "/cmd", CWD: cwd}
			h.workspaces[h.current].Files = append(h.workspaces[h.current].Files, f)
		} else {
			f = h.file(id)
		}
		if f == nil || f.Type != "shell" {
			h.mu.Unlock()
			http.Error(w, "Command tab not found", 404)
			return
		}
		if previous := h.runs[id]; previous != nil {
			previous.cancel()
		}
	} else {
		h.nextID++
		id = -h.nextID
	}
	h.runs[id] = run
	h.mu.Unlock()
	output, runErr := cmd.CombinedOutput()
	// CommandContext no longer calls Cancel once the shell has exited. On a
	// failed exit, Go reports the exit error even if WaitDelay also expired
	// waiting for a child that still holds an output pipe.
	if runErr != nil {
		_ = cmd.Cancel()
	}
	close(run.done)
	h.mu.Lock()
	if h.runs[id] != run {
		h.mu.Unlock()
		http.Error(w, "Command replaced", 409)
		return
	}
	delete(h.runs, id)
	if !quick && !h.closed {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			f.CWD = lines[len(lines)-2]
		}
		if err := h.save(); err != nil {
			if fresh {
				for i, file := range h.workspaces[h.current].Files {
					if file == f {
						h.workspaces[h.current].Files = append(h.workspaces[h.current].Files[:i], h.workspaces[h.current].Files[i+1:]...)
						break
					}
				}
			}
			h.mu.Unlock()
			http.Error(w, "Could not save command tab", 500)
			return
		}
		if fresh {
			w.Header().Set("X-ID", strconv.Itoa(id))
		}
	}
	h.mu.Unlock()
	if runErr != nil && len(output) == 0 {
		http.Error(w, runErr.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}
func (h *Handler) saveLoad(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("fullpath")
	if before, after, ok := strings.Cut(raw, ":"); ok {
		if _, err := strconv.Atoi(after); err == nil {
			raw = before
		}
	}
	target := h.fullPath(raw)
	if r.Method == "POST" {
		// Serialize the checksum read and write so two saves cannot both accept
		// the same old version and silently overwrite each other.
		h.mu.Lock()
		fileSaveMu.Lock()
		locked := true
		unlock := func() {
			fileSaveMu.Unlock()
			h.mu.Unlock()
			locked = false
		}
		defer func() {
			if locked {
				unlock()
			}
		}()
		fail := func(message string, code int) {
			unlock()
			http.Error(w, message, code)
		}
		if h.closed {
			fail("Editor closed", 503)
			return
		}
		content := r.FormValue("content")
		diff := r.FormValue("diff")
		if diff != "" && r.FormValue("oldmd5") != "" && r.FormValue("newmd5") != "" {
			old, err := os.ReadFile(target)
			if err != nil {
				fail("Could not read file", 400)
				return
			}
			if hash(old) != r.FormValue("oldmd5") {
				fail("File changed since it was loaded", 409)
				return
			}
			content, err = ApplyDiff(string(old), diff)
			if err != nil || hash([]byte(content)) != r.FormValue("newmd5") {
				fail("File diff checksum mismatch", 400)
				return
			}
		} else if content == "" {
			fail("Empty content", 400)
			return
		}
		err := os.WriteFile(target, []byte(content), 0644)
		unlock()
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{"saved": err == nil}
		if err != nil {
			response["error"] = err.Error()
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	info, err := os.Stat(target)
	if err != nil {
		http.Error(w, "File unavailable", 404)
		return
	}
	kind := "file"
	var data []byte
	if info.IsDir() {
		kind = "directory"
		entries, err := os.ReadDir(target)
		if err != nil {
			http.Error(w, "Directory unavailable", 404)
			return
		}
		names := []string{".."}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		data = []byte(strings.Join(names, "\n"))
		w.Header().Set("X-Is-Dir", "1")
	} else {
		data, err = os.ReadFile(target)
		if err != nil {
			http.Error(w, "Could not read file", 500)
			return
		}
		w.Header().Set("X-MD5", hash(data))
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "Editor closed", 503)
		return
	}
	if r.FormValue("noid") != "1" {
		id, _ := strconv.Atoi(r.FormValue("id"))
		fresh := id == 0
		if fresh {
			h.nextID++
			id = h.nextID
			h.workspaces[h.current].Files = append(h.workspaces[h.current].Files, &File{ID: id, Type: kind, FullPath: target})
			w.Header().Set("X-ID", strconv.Itoa(id))
		}
		if err := h.save(); err != nil {
			if fresh {
				h.workspaces[h.current].Files = h.workspaces[h.current].Files[:len(h.workspaces[h.current].Files)-1]
				h.nextID--
			}
			h.mu.Unlock()
			http.Error(w, "Could not save workspace", 500)
			return
		}
	}
	h.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}
