package editor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func request(h *Handler, method, url, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, url, strings.NewReader(body)))
	return w
}
func newTestHandler(t *testing.T, state string) *Handler {
	t.Helper()
	h, err := New(Config{MountPath: "/editor", StateFile: state, ScriptURL: "/client.js"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}
func snapshot(t *testing.T, h *Handler) *Workspace {
	t.Helper()
	w := request(h, "GET", "/editor/myWorkspaceWithList", "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct{ Workspace *Workspace }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Workspace
}

func TestMountAssetsAndIsolation(t *testing.T) {
	cwd, _ := os.Getwd()
	a := newTestHandler(t, filepath.Join(t.TempDir(), "a.json"))
	b := newTestHandler(t, filepath.Join(t.TempDir(), "b.json"))
	if after, _ := os.Getwd(); after != cwd {
		t.Fatal("constructor changed process cwd")
	}
	for _, h := range []*Handler{a, b} {
		w := request(h, "GET", "/editor/", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `var proxyPath = "/editor"`) || !strings.Contains(w.Body.String(), `src="/client.js"`) {
			t.Fatal("missing embedded frontend configuration")
		}
		if strings.Contains(w.Body.String(), `<script src="https://unpkg.com/sval`) {
			t.Fatal("text mode loaded optional script interpreter")
		}
		for _, asset := range []string{"md52.js", "text-controls.js"} {
			if w := request(h, "GET", "/editor/tepublic/"+asset, ""); w.Code != 200 {
				t.Fatalf("embedded asset %s not served", asset)
			}
		}
		for _, url := range []string{"/editors/", "/editor/tepublic/../handler.go", "/editor/tepublic/missing"} {
			if w := request(h, "GET", url, ""); w.Code != 404 {
				t.Fatalf("%s: %d", url, w.Code)
			}
		}
		for _, url := range []string{"/editor/myshell", "/editor/saveload", "/editor/myterminalopen"} {
			if w := request(h, "GET", url, ""); w.Code != 403 {
				t.Fatalf("%s: %d", url, w.Code)
			}
		}
	}
	if w := request(a, "GET", "/editor/myaddfile?fileType=devtracker&fullPath=42", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if len(snapshot(t, a).Files) != 2 || len(snapshot(t, b).Files) != 1 {
		t.Fatal("instances shared state")
	}
}

func TestPersistenceAndClientCannotChangeIdentity(t *testing.T) {
	state := filepath.Join(t.TempDir(), "workspaces.json")
	h := newTestHandler(t, state)
	w := request(h, "GET", "/editor/myaddfile?fileType=devtracker&fullPath=42", "")
	id := w.Header().Get("X-ID")
	body := fmt.Sprintf(`{"Name":"default","Files":[{"ID":%s,"Type":"terminal","FullPath":"/etc/passwd","Name":"Renamed","Pinned":true}],"FontScale":1.2}`, id)
	if w := request(h, "POST", "/editor/mysaveworkspace", body); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	stored := snapshot(t, h)
	if stored.Files[0].Type != "devtracker" || stored.Files[0].FullPath != "42" || stored.Files[0].Name != "Renamed" || !stored.Files[0].Pinned {
		t.Fatalf("lost identity or metadata: %+v", stored.Files[0])
	}
	if info, err := os.Stat(state); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("workspace is not private")
	}
	_ = h.Close()
	reopened := newTestHandler(t, state)
	if got := snapshot(t, reopened); len(got.Files) != 2 || got.Files[0].Name != "Renamed" || got.FontScale != 1.2 {
		t.Fatalf("lost persisted state: %+v", got)
	}
	if w := request(reopened, "GET", "/editor/myclose?id="+id, ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	again := newTestHandler(t, state)
	if len(snapshot(t, again).Files) != 1 {
		t.Fatal("closed tab resurrected")
	}
}

func TestFailedSaveRollsBack(t *testing.T) {
	dir := t.TempDir()
	h := newTestHandler(t, filepath.Join(dir, "state", "workspaces.json"))
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	w := request(h, "GET", "/editor/myaddfile?fileType=devtracker&fullPath=42", "")
	if w.Code != 500 {
		t.Fatalf("save error hidden: %d", w.Code)
	}
	if len(snapshot(t, h).Files) != 1 {
		t.Fatal("failed mutation changed memory state")
	}
	if w.Header().Get("X-ID") != "" {
		t.Fatal("failed tab creation returned a successful ID")
	}
}

func TestConcurrentInstances(t *testing.T) {
	a, b := newTestHandler(t, ""), newTestHandler(t, "")
	var group sync.WaitGroup
	for _, h := range []*Handler{a, b} {
		for i := 1; i <= 20; i++ {
			group.Add(1)
			go func(h *Handler, id int) {
				defer group.Done()
				if w := request(h, "GET", fmt.Sprintf("/editor/myaddfile?fileType=devtracker&fullPath=%d", id), ""); w.Code != 200 {
					t.Errorf("create failed: %s", w.Body.String())
				}
			}(h, i)
		}
	}
	group.Wait()
	for _, h := range []*Handler{a, b} {
		got := snapshot(t, h)
		if len(got.Files) != 21 {
			t.Fatal("concurrent tab lost")
		}
		ids := map[int]bool{}
		for _, f := range got.Files {
			if ids[f.ID] {
				t.Fatal("duplicate tab ID")
			}
			ids[f.ID] = true
		}
	}
}

type blockedResponseWriter struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedResponseWriter) Header() http.Header { return w.header }
func (w *blockedResponseWriter) WriteHeader(int)     {}
func (w *blockedResponseWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(data), nil
}

func TestSlowResponseDoesNotHoldStateLock(t *testing.T) {
	for _, route := range []string{"/editor/", "/editor/myWorkspaceWithList"} {
		t.Run(route, func(t *testing.T) {
			h := newTestHandler(t, "")
			writer := &blockedResponseWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
			defer close(writer.release)
			go h.ServeHTTP(writer, httptest.NewRequest("GET", route, nil))
			select {
			case <-writer.entered:
			case <-time.After(time.Second):
				t.Fatal("response did not start")
			}
			done := make(chan int, 1)
			go func() { done <- request(h, "GET", "/editor/myaddfile?fileType=devtracker&fullPath=42", "").Code }()
			select {
			case status := <-done:
				if status != 200 {
					t.Fatalf("mutation status %d", status)
				}
			case <-time.After(time.Second):
				t.Fatal("slow response blocked state mutation")
			}
			closed := make(chan struct{})
			go func() { h.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("slow response blocked Close")
			}
		})
	}
}

func TestRelativeStatePathIsBoundAtConstruction(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "workspace.json")
	relative, err := filepath.Rel(cwd, target)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(t, relative)
	if h.config.StateFile != target {
		t.Fatalf("state path not anchored: %q", h.config.StateFile)
	}
}

func TestDiffTabPersistence(t *testing.T) {
	state := filepath.Join(t.TempDir(), "workspace.json")
	h := newTestHandler(t, state)
	if w := request(h, "GET", "/editor/myaddfile?fileType=devtracker-diff&fullPath=42", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	restored := newTestHandler(t, state)
	tabs := snapshot(t, restored).Files
	if len(tabs) != 2 || tabs[1].Type != "devtracker-diff" || tabs[1].FullPath != "42" {
		t.Fatalf("diff tab not restored: %+v", tabs)
	}
	other := newTestHandler(t, filepath.Join(t.TempDir(), "other.json"))
	if len(snapshot(t, other).Files) != 1 {
		t.Fatal("diff tab leaked between users")
	}
	for _, id := range []string{"0", "-1", "file.txt"} {
		if w := request(h, "GET", "/editor/myaddfile?fileType=devtracker-diff&fullPath="+id, ""); w.Code == 200 {
			t.Fatalf("accepted invalid task ID %s", id)
		}
	}
}
