package editor

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalCommandAndFileFlow(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "example.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{MountPath: "/editor", EnableEditor: true, Directory: root, StateFile: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if snapshot(t, h).Files[0].Type != "directory" {
		t.Fatal("normal editor must start with its directory")
	}
	r := request(h, "GET", "/editor/saveload?raw=1&fullpath="+url.QueryEscape(root), "")
	if r.Code != 200 || r.Header().Get("X-Is-Dir") != "1" || !strings.Contains(r.Body.String(), "example.txt") {
		t.Fatalf("open .: %d %s", r.Code, r.Body.String())
	}
	r = request(h, "GET", "/editor/myshell?cwd="+url.QueryEscape(root)+"&cmd="+url.QueryEscape("printf 'normal command'"), "")
	id := r.Header().Get("X-ID")
	if r.Code != 200 || id == "" || r.Body.String() != "normal command\n"+root+"\n" {
		t.Fatalf("new cmd: %d %s", r.Code, r.Body.String())
	}
	r = request(h, "GET", "/editor/myshell?id="+id+"&cwd="+url.QueryEscape(root)+"&cmd="+url.QueryEscape("cd sub; printf 'next'"), "")
	if r.Code != 200 || !strings.HasSuffix(r.Body.String(), root+"/sub\n") {
		t.Fatal("cmd did not preserve directory changes")
	}
	r = request(h, "GET", "/editor/saveload?raw=1&fullpath="+url.QueryEscape(filepath.Join(root, "example.txt")), "")
	if r.Code != 200 || r.Body.String() != "before\n" || r.Header().Get("X-MD5") != hash([]byte("before\n")) {
		t.Fatal("file open changed")
	}
	req := httptest.NewRequest("POST", "/editor/saveload?fullpath="+url.QueryEscape(filepath.Join(root, "example.txt")), strings.NewReader("content=after%0A"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"saved":true`) {
		t.Fatal("file save failed")
	}
	data, _ := os.ReadFile(filepath.Join(root, "example.txt"))
	if string(data) != "after\n" {
		t.Fatal("file content not saved")
	}
}

func TestOldTaskCommandMigratesToNormalShell(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(state, []byte(`[{"Name":"default","Files":[{"ID":1,"Type":"dtai-command","FullPath":"cmd"}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	h, err := New(Config{EnableEditor: true, Directory: root, StateFile: state})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	f := h.workspaces[0].Files[0]
	if f.Type != "shell" || f.CWD != root {
		t.Fatalf("old command not migrated: %+v", f)
	}
}

func TestClosingEditorStopsCommand(t *testing.T) {
	h, err := New(Config{MountPath: "/editor", EnableEditor: true, Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { request(h, "GET", "/editor/myshell?cmd=sleep+30", ""); close(done) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		running := len(h.runs) > 0
		h.mu.Unlock()
		if running {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("command survived editor close")
	}
}
