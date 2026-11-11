package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDevTrackerWorkspaceSave(t *testing.T) {
	oldMode, oldPath, oldWorkspaces := devTrackerMode, workspacesFile, workspaces
	defer func() { devTrackerMode, workspacesFile, workspaces = oldMode, oldPath, oldWorkspaces }()
	devTrackerMode = true
	dir := t.TempDir()
	workspacesFile = filepath.Join(dir, "workspaces.json")
	workspaces = []*Workspace{{Name: "mobile", Files: []*File{{ID: 1, Type: "devtracker", FullPath: "42"}}}}
	w := httptest.NewRecorder()
	writeWorkspaceFile(w, httptest.NewRequest("POST", "/mysaveworkspace", nil))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	data, err := os.ReadFile(workspacesFile)
	if err != nil {
		t.Fatal(err)
	}
	var stored []map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0]["Name"] != "mobile" {
		t.Fatalf("unexpected saved workspace: %s", data)
	}
	info, err := os.Stat(workspacesFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private workspace mode %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("save left temporary files: %v", entries)
	}
	workspacesFile = filepath.Join(dir, "missing", "workspaces.json")
	w = httptest.NewRecorder()
	writeWorkspaceFile(w, httptest.NewRequest("POST", "/mysaveworkspace", nil))
	if w.Code != 500 {
		t.Fatalf("save failure returned %d: %s", w.Code, w.Body.String())
	}
}
