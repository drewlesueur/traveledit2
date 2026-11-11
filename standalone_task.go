package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	assets "github.com/drewlesueur/traveledit2/public"
)

type standaloneTaskOptions struct {
	mountPath           string
	directory           string
	prefixTrimmed       bool
	loginFile           string
	allowedIPs          map[string]bool
	allowedForwardedIPs map[string]bool
}

// Authentication belongs to the standalone host, never to the embedded editor.
// Preserve its cookie login and explicit network restrictions without relying
// on the legacy server's package-global proxy path.
func standaloneTaskHandler(app http.Handler, options standaloneTaskOptions) (http.Handler, error) {
	mount := strings.TrimSuffix(options.mountPath, "/")
	useAuth := os.Getenv("NOBASICAUTH") == ""
	user, password := os.Getenv("BASICUSER"), os.Getenv("BASICPASS")
	if useAuth && (user == "" || password == "") {
		return nil, fmt.Errorf("BASICUSER and BASICPASS are required for standalone authentication")
	}
	var login []byte
	if useAuth {
		var err error
		if options.loginFile != "" {
			login, err = os.ReadFile(options.loginFile)
		}
		if options.loginFile == "" || (options.loginFile == "./public/login.html" && os.IsNotExist(err)) {
			login, err = assets.Files.ReadFile("login.html")
		}
		if err != nil {
			return nil, fmt.Errorf("read standalone login: %w", err)
		}
		quotedMount, _ := json.Marshal(mount)
		login = bytes.Replace(login, []byte("// PROXYPATH GOES HERE"), append([]byte("var proxyPath = "), quotedMount...), 1)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if len(options.allowedIPs) > 0 && !options.allowedIPs[host] {
			http.Error(w, "Address not allowed", 403)
			return
		}
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
		if len(options.allowedForwardedIPs) > 0 && !options.allowedForwardedIPs[forwarded] {
			http.Error(w, "Forwarded address not allowed", 403)
			return
		}
		local := r.URL.Path
		if !options.prefixTrimmed && mount != "" {
			if local != mount && !strings.HasPrefix(local, mount+"/") {
				http.NotFound(w, r)
				return
			}
			local = strings.TrimPrefix(local, mount)
		}
		if local == "" {
			local = "/"
		}
		if useAuth && local == "/login" {
			if r.Method != "GET" && r.Method != "HEAD" {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "Method not allowed", 405)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			http.ServeContent(w, r, "login.html", time.Time{}, bytes.NewReader(login))
			return
		}
		if useAuth && !strings.HasPrefix(local, "/tepublic/") {
			gotUser, gotPassword, ok := PretendBasicAuth(r)
			if !ok || subtle.ConstantTimeCompare([]byte(gotUser), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(gotPassword), []byte(password)) != 1 {
				http.Redirect(w, r, mount+"/login", http.StatusFound)
				return
			}
		}
		if options.prefixTrimmed {
			r = r.Clone(r.Context())
			r.URL.Path = mount + local
			r.URL.RawPath = ""
		}
		app.ServeHTTP(w, r)
	}), nil
}
