# TravelEdit2

The existing standalone file/terminal editor still runs with `go run .` or a
compiled `traveledit` executable and its normal flags and authentication.

## Embedding text tabs

The `editor` package serves the same text-canvas frontend as an `http.Handler`.
It currently exposes task text tabs and their workspace APIs; host filesystem
and terminal APIs remain in the standalone executable.

```go
import "github.com/drewlesueur/traveledit2/editor"

app, err := editor.New(editor.Config{
    MountPath: "/editor",
    StateFile: "/private/state/workspaces.json",
    ScriptURL: "/my-task-client.js",
})
if err != nil {
    return err
}
defer app.Close()
mux.Handle("/editor/", app) // Wrap with the host's authentication.
```

Construct one handler per user to isolate workspaces. `StateFile` can be empty
for in-memory state; when set, use a separate private file for each handler.
Writes are serialized and atomically replace the file before acknowledging a
mutation. Existing task-mode workspace JSON is supported. `Close` blocks until
an active handler request finishes and then rejects new requests.

`ScriptURL` identifies the host's text-tab adapter (for example, DevTracker's
message reader/composer). Provide this adapter when using the default assets with task tabs; a custom
`Assets` filesystem can include its own adapter instead. The library does not
contain task credentials, a task database, or a message service. `Assets` can optionally
provide an `fs.FS` with additional fonts/assets; the default embeds `index.html`
and `md52.js` from the same `public` directory used by the standalone editor.
No source checkout is read at runtime by the default embedded handler.

Creating a handler does not register global flags, change cwd/environment,
start goroutines, bind a socket, or launch a process. The package and its default
assets depend only on the Go standard library.

The standalone `DEVTRACKER_MODE=1` entry point also uses this package, so its
workspace behavior and the embedded behavior share one implementation. It
retains the usual `-addr`, `-unix-socket`, `-proxypath`, `WORKSPACES_FILE`, and
`NOBASICAUTH` settings; `TRAVELEDIT_SCRIPT_URL` overrides its host adapter URL.
The default standalone file/terminal mode remains independent of DevTracker.

Run `go test -race ./editor ./public` for package checks. The legacy executable's
existing example names currently require `go test -vet=off ./...`.
