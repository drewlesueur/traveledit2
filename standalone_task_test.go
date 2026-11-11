package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandaloneTaskLoginAndMount(t *testing.T) {
	t.Setenv("NOBASICAUTH", "")
	t.Setenv("BASICUSER", "fixture")
	t.Setenv("BASICPASS", "fixture-password")
	for _, trimmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "full-prefix", true: "trimmed-prefix"}[trimmed], func(t *testing.T) {
			reached := ""
			app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = r.URL.Path; w.Write([]byte("ok")) })
			handler, err := standaloneTaskHandler(app, standaloneTaskOptions{mountPath: "/te", prefixTrimmed: trimmed})
			if err != nil {
				t.Fatal(err)
			}
			target := "/te/workspace"
			login := "/te/login"
			if trimmed {
				target = "/workspace"
				login = "/login"
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
			if w.Code != 302 || w.Header().Get("Location") != "/te/login" || reached != "" {
				t.Fatalf("unauthenticated request reached editor: %d %q", w.Code, reached)
			}
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", login, nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "saveCookie") {
				t.Fatalf("login unavailable: %d %s", w.Code, w.Body.String())
			}
			req := httptest.NewRequest("GET", target, nil)
			req.AddCookie(&http.Cookie{Name: "pretendba", Value: url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("fixture:fixture-password")))})
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != 200 || reached != "/te/workspace" {
				t.Fatalf("authenticated mount: %d %q", w.Code, reached)
			}
		})
	}
}

func TestStandaloneTaskNetworkRestrictions(t *testing.T) {
	t.Setenv("NOBASICAUTH", "1")
	handler, err := standaloneTaskHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), standaloneTaskOptions{
		allowedIPs: map[string]bool{"127.0.0.1": true}, allowedForwardedIPs: map[string]bool{"192.0.2.1": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		remote, forwarded string
		status            int
	}{
		{"127.0.0.1:1234", "192.0.2.1", 204}, {"127.0.0.2:1234", "192.0.2.1", 403}, {"127.0.0.1:1234", "192.0.2.2", 403},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", tc.forwarded)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%+v: got %d", tc, w.Code)
		}
	}
}

func TestStandaloneTaskCustomLogin(t *testing.T) {
	t.Setenv("NOBASICAUTH", "")
	t.Setenv("BASICUSER", "fixture")
	t.Setenv("BASICPASS", "fixture-password")
	login := filepath.Join(t.TempDir(), "login.html")
	if err := os.WriteFile(login, []byte("custom login\n// PROXYPATH GOES HERE"), 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := standaloneTaskHandler(http.NotFoundHandler(), standaloneTaskOptions{mountPath: "/te", loginFile: login})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/te/login", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "custom login") || !strings.Contains(w.Body.String(), `var proxyPath = "/te"`) {
		t.Fatal("custom login was not configured")
	}
}
