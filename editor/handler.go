// Package editor embeds TravelEdit's text-tab workspace in an existing HTTP
// server. Each Handler owns its state; constructing one never starts a listener,
// goroutine, shell, or subprocess, and does not change flags, cwd, or environment.
// The host is responsible for authentication and selecting the user's Handler.
package editor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	assets "github.com/drewlesueur/traveledit2/public"
)

// Config configures one independent text-only editor workspace collection.
// StateFile may be empty for an in-memory editor. Only one live Handler should
// own a given state file. MountPath must match the route used by the host.
// ScriptURL supplies the host's task-tab integration, including its message API.
type Config struct {
	MountPath string
	StateFile string
	ScriptURL string
	Assets    fs.FS
	// EnableEditor enables the normal command and file APIs for trusted users.
	EnableEditor bool
	Directory    string
}

type File struct {
	ID              int
	Type            string
	FullPath        string
	Name            string
	LineNumber      int
	CWD             string
	Color           string
	Group           string
	Pinned          bool
	HighlightText   string
	HighlightRanges json.RawMessage
}

type Workspace struct {
	Name             string
	Files            []*File
	DarkMode         bool
	InDebugView      bool
	FontName         string
	FontScale        float64
	HighlightMatches json.RawMessage
	PathDecorators   json.RawMessage
}

// Handler implements http.Handler and owns all of its mutable workspace state.
// Task tabs are always supported. EnableEditor adds the normal TravelEdit
// command and file APIs; the embedding host must authorize that capability.
type Handler struct {
	mu         sync.Mutex
	config     Config
	index      []byte
	workspaces []*Workspace
	current    int
	nextID     int
	closed     bool
	runs       map[int]*commandRun
	terminals  map[int]*terminalRun
}

func New(config Config) (*Handler, error) {
	if config.EnableEditor {
		directory := config.Directory
		if directory == "" {
			var err error
			directory, err = os.Getwd()
			if err != nil {
				return nil, err
			}
		}
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return nil, err
		}
		config.Directory = absolute
	}
	if config.StateFile != "" {
		absolute, err := filepath.Abs(config.StateFile)
		if err != nil {
			return nil, fmt.Errorf("resolve editor state path: %w", err)
		}
		config.StateFile = absolute
	}

	if config.MountPath == "/" {
		config.MountPath = ""
	}
	if config.MountPath != "" && (!strings.HasPrefix(config.MountPath, "/") || strings.ContainsAny(config.MountPath, "?#") || path.Clean(config.MountPath) != config.MountPath) {
		return nil, fmt.Errorf("invalid editor mount path %q", config.MountPath)
	}
	if config.Assets == nil {
		config.Assets = assets.Files
	}
	index, err := fs.ReadFile(config.Assets, "index.html")
	if err != nil {
		return nil, fmt.Errorf("load editor frontend: %w", err)
	}
	mount, _ := json.Marshal(config.MountPath)
	index = bytes.Replace(index, []byte("// PROXYPATH GOES HERE"), append([]byte("var proxyPath = "), mount...), 1)
	// Task tabs do not execute editor scripts or depend on the optional Sval CDN.
	index = bytes.Replace(index, []byte(`<script src="https://unpkg.com/sval@0.4.8/dist/sval.min.js"></script>`), nil, 1)
	if config.ScriptURL != "" {
		script := []byte(`<script src="` + html.EscapeString(config.ScriptURL) + `"></script>`)
		index = bytes.Replace(index, []byte("</head>"), append(script, []byte("</head>")...), 1)
	}
	index = bytes.Replace(index, []byte("</head>"), []byte("<script>window.travelEditEmbedded = true;</script></head>"), 1)
	h := &Handler{config: config, index: index}
	if config.StateFile != "" {
		data, readErr := os.ReadFile(config.StateFile)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return nil, fmt.Errorf("read editor state: %w", readErr)
		}
		if readErr == nil {
			if err := json.Unmarshal(data, &h.workspaces); err != nil {
				return nil, fmt.Errorf("decode editor state: %w", err)
			}
		}
	}
	seen := map[int]bool{}
	for _, w := range h.workspaces {
		if w == nil {
			return nil, errors.New("nil editor workspace")
		}
		if w.Files == nil {
			w.Files = []*File{}
		}
		for _, f := range w.Files {
			if f != nil && f.Type == "dtai-command" && config.EnableEditor {
				f.Type = "shell"
				f.CWD = config.Directory
				f.FullPath = config.MountPath + "/cmd"
			}
			if f == nil || !h.validFile(f) || f.ID <= 0 || seen[f.ID] {
				return nil, errors.New("invalid editor tab in saved workspace")
			}
			seen[f.ID] = true
			if f.ID > h.nextID {
				h.nextID = f.ID
			}
		}
	}
	if len(h.workspaces) == 0 {
		h.workspaces = []*Workspace{h.newWorkspace("default")}
	}
	return h, nil
}

func validTab(kind, fullPath string) bool {
	if kind == "dtai-command" {
		return fullPath == "cmd"
	}
	id, err := strconv.ParseInt(fullPath, 10, 64)
	return (kind == "devtracker" || kind == "devtracker-diff" || kind == "devtracker-accept-diff") && err == nil && id > 0 && strconv.FormatInt(id, 10) == fullPath
}
func (h *Handler) newWorkspace(name string) *Workspace {
	h.nextID++
	if h.config.EnableEditor {
		return &Workspace{Name: name, Files: []*File{{ID: h.nextID, Type: "directory", FullPath: h.config.Directory}}}
	}
	return &Workspace{Name: name, Files: []*File{{ID: h.nextID, Type: "dtai-command", FullPath: "cmd"}}}
}

// Close prevents further requests and waits for active state mutations.
// Active commands are canceled and reaped. Responses already captured may
// finish sending; slow clients cannot hold the state lock.
func (h *Handler) Close() error {
	h.mu.Lock()
	h.closed = true
	runs := make([]*commandRun, 0, len(h.runs))
	for _, run := range h.runs {
		run.cancel()
		runs = append(runs, run)
	}
	for _, terminal := range h.terminals {
		terminal.stop()
		runs = append(runs, &commandRun{done: terminal.done})
	}
	h.mu.Unlock()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for _, run := range runs {
		select {
		case <-run.done:
		case <-timeout.C:
			return fmt.Errorf("command shutdown timed out")
		}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := r.URL.Path
	if h.config.MountPath != "" {
		if route != h.config.MountPath && !strings.HasPrefix(route, h.config.MountPath+"/") {
			http.NotFound(w, r)
			return
		}
		route = strings.TrimPrefix(route, h.config.MountPath)
	}
	if route == "" {
		route = "/"
	}
	w.Header().Set("Cache-Control", "no-store")
	if h.config.EnableEditor && h.serveEditor(w, r, route) {
		return
	}
	h.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			h.mu.Unlock()
			locked = false
		}
	}
	defer unlock()
	if h.closed {
		unlock()
		http.Error(w, "Editor closed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if route == "/" && (r.Method == "GET" || r.Method == "HEAD") {
		unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(h.index))
		return
	}
	if strings.HasPrefix(route, "/tepublic/") && (r.Method == "GET" || r.Method == "HEAD") {
		unlock()
		name := strings.TrimPrefix(route, "/tepublic/")
		if !fs.ValidPath(name) || name == "." {
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(h.config.Assets, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
		return
	}
	// These are the workspace endpoints used by the existing TravelEdit client.
	if route != "/myWorkspaceWithList" && route != "/myaddfile" && route != "/myclose" && route != "/myname" && route != "/mysaveworkspace" {
		unlock()
		http.Error(w, "This workspace supports task text tabs only", http.StatusForbidden)
		return
	}
	if r.Method != "GET" && r.Method != "POST" || route == "/mysaveworkspace" && r.Method != "POST" {
		unlock()
		allowed := "GET, POST"
		if route == "/mysaveworkspace" {
			allowed = "POST"
		}
		w.Header().Set("Allow", allowed)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Keep an independent rollback copy until atomic persistence succeeds.
	before, err := json.Marshal(h.workspaces)
	if err != nil {
		unlock()
		http.Error(w, "Could not snapshot editor state", 500)
		return
	}
	oldCurrent, oldID := h.current, h.nextID
	rollback := func() { _ = json.Unmarshal(before, &h.workspaces); h.current = oldCurrent; h.nextID = oldID }
	fail := func(code int, message string) { rollback(); unlock(); http.Error(w, message, code) }
	current := h.workspaces[h.current]
	var terminalToClose *terminalRun
	var result any
	newID := 0
	changed := false
	switch route {
	case "/myWorkspaceWithList":
		index := r.FormValue("index")
		if index == "new" {
			h.workspaces = append(h.workspaces, h.newWorkspace("workspace "+strconv.Itoa(len(h.workspaces)+1)))
			h.current = len(h.workspaces) - 1
			changed = true
		} else if index != "" {
			n, err := strconv.Atoi(index)
			if err != nil || n < 0 || n >= len(h.workspaces) {
				fail(400, "Invalid workspace index")
				return
			}
			h.current = n
		}
		names := make([]map[string]string, 0, len(h.workspaces))
		for _, ws := range h.workspaces {
			names = append(names, map[string]string{"Name": ws.Name})
		}
		result = map[string]any{"workspace": h.workspaces[h.current], "workspacesList": names}
	case "/myaddfile":
		kind, fullPath := r.FormValue("fileType"), r.FormValue("fullPath")
		if !h.validFile(&File{Type: kind, FullPath: fullPath}) {
			fail(403, "Unsupported task tab")
			return
		}
		h.nextID++
		newID = h.nextID
		current.Files = append(current.Files, &File{ID: newID, Type: kind, FullPath: fullPath})
		changed = true
	case "/myclose", "/myname":
		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil || id <= 0 {
			fail(400, "Invalid tab ID")
			return
		}
		found := false
		for i, f := range current.Files {
			if f.ID != id {
				continue
			}
			found = true
			if route == "/myclose" {
				if terminal := h.terminals[id]; terminal != nil {
					terminalToClose = terminal
				}
				if run := h.runs[id]; run != nil {
					run.cancel()
				}
				current.Files = append(current.Files[:i], current.Files[i+1:]...)
			} else {
				f.Name = r.FormValue("name")
			}
			changed = true
			break
		}
		if !found {
			fail(404, "Tab not found")
			return
		}
	case "/mysaveworkspace":
		var incoming Workspace
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&incoming); err != nil {
			fail(400, "Invalid workspace")
			return
		}
		name := r.FormValue("oldWorkspaceName")
		if name == "" {
			name = incoming.Name
		}
		if name != current.Name {
			fail(409, "Workspace changed; reload before saving")
			return
		}
		existing := map[int]*File{}
		for _, f := range current.Files {
			existing[f.ID] = f
		}
		ordered := make([]*File, 0, len(current.Files))
		for _, edit := range incoming.Files {
			if edit == nil {
				continue
			}
			f := existing[edit.ID]
			if f == nil {
				continue
			}
			// Tab identity and type belong to the server, not editable client metadata.
			f.Name = edit.Name
			f.LineNumber = edit.LineNumber
			f.Color = edit.Color
			f.Group = edit.Group
			f.Pinned = edit.Pinned
			f.HighlightText = edit.HighlightText
			f.HighlightRanges = edit.HighlightRanges
			ordered = append(ordered, f)
			delete(existing, f.ID)
		}
		for _, f := range current.Files {
			if existing[f.ID] != nil {
				ordered = append(ordered, f)
			}
		}
		incoming.Files = ordered
		h.workspaces[h.current] = &incoming
		changed = true
	}
	if changed {
		if err := h.save(); err != nil {
			fail(500, "Could not save editor workspace")
			return
		}
	}
	if newID != 0 {
		w.Header().Set("X-ID", strconv.Itoa(newID))
	}
	w.Header().Set("Content-Type", "application/json")
	if result == nil {
		result = map[string]bool{"ok": true}
	}
	data, err := json.Marshal(result)
	if err != nil {
		unlock()
		http.Error(w, "Could not encode editor response", 500)
		return
	}
	if terminalToClose != nil {
		id, _ := strconv.Atoi(r.FormValue("id"))
		delete(h.terminals, id)
	}
	unlock()
	if terminalToClose != nil {
		terminalToClose.stop()
		<-terminalToClose.done
	}
	_, _ = w.Write(append(data, '\n'))
}

func (h *Handler) save() error {
	if h.config.StateFile == "" {
		return nil
	}
	data, err := json.MarshalIndent(h.workspaces, "", "    ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(h.config.StateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".workspace-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), h.config.StateFile)
}
