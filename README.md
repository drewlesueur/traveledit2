# TravelEdit2

The existing standalone file/terminal editor still runs with `go run .` or a
compiled `traveledit` executable and its normal flags and authentication.

## Embedding text tabs

The `editor` package serves the same text-canvas frontend as an `http.Handler`.
It exposes task text tabs and, with `EnableEditor`, the ordinary command and
file APIs used by TravelEdit. The host controls authentication and access.

```go
import "github.com/drewlesueur/traveledit2/editor"

app, err := editor.New(editor.Config{
    MountPath: "/editor",
    EnableEditor: true,
    Directory: "/path/to/project",
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
Relative state paths are resolved once at construction. Writes are serialized
and atomically replace the file before acknowledging a mutation. Existing
task-mode workspace JSON is supported. `Close` waits for active state mutations
and then rejects new requests. Response bytes already captured may finish
sending; slow clients do not hold the workspace lock or delay shutdown.

`ScriptURL` identifies the host's text-tab adapter (for example, DevTracker's
message reader/composer). Provide this adapter when using the default assets
with task tabs; a custom `Assets` filesystem can include its own adapter instead.
The library does not contain task credentials, a task database, or a message
service. `Assets` can optionally provide an `fs.FS` with additional fonts/assets;
the default embeds `index.html`, `md52.js`, `text-controls.js`, and the standalone login form from
the same `public` directory used by the standalone editor. No source checkout
is read at runtime by the default embedded handler.

Creating a handler does not register global flags, change process cwd or
environment, bind a socket, or launch an editor process. Ordinary `cmd` requests
launch shell commands when `EnableEditor` is enabled; closing the handler stops
its active commands. Leave that option off for hosts that only need task tabs.
The package and its default assets depend only on the Go standard library.

The standalone `DEVTRACKER_MODE=1` entry point also uses this package, so its
workspace behavior and the embedded behavior share one implementation. It
retains the usual `-addr`, `-unix-socket`, `-proxypath`, `WORKSPACES_FILE`, and
`NOBASICAUTH` settings. Standalone cookie login, configured address filters,
and `-proxypathtrimmed` are honored. `TRAVELEDIT_SCRIPT_URL` overrides the
host adapter URL.
The default standalone file/terminal mode remains independent of DevTracker.

Run `go test -race ./editor ./public` for package checks and
`node test-directory-reload.js` for duplicate-directory loading and refresh checks.
Run `node test-editor-ui.js` for host-control sizing checks.
The legacy executable's existing example names currently require `go test -vet=off ./...`.

## Reusable text controls

Both the standalone editor and embedded editor load `public/text-controls.js`.
`TravelEditUI.createControls()` renders buttons, radio choices, and nested popups
as ordinary fixed-width text with Unicode borders and shadows. It creates no DOM
controls and knows nothing about DevTracker or model APIs.

```js
const controls = TravelEditUI.createControls({ onChange: redraw });
controls.setContent([controls.button('[ Tools > ]', () => {
    const tools = controls.open('Tools');
    tools.radioGroup('Density', ['compact', 'comfortable'], 'compact', value => {
        density = value;
    });
    tools.button('[ Done ]', () => controls.closeAll({ focus: true }));
    controls.refresh({ focus: true });
})]);
file.textControls = controls;
// In redraw(), append these immutable rows after your editable content:
const result = controls.render({ startRow, width, viewportStart, viewportRows });
// Append result.lines to file.lines. Keep them outside the editable range.
```

The native middle-region tap and Enter activate `file.textControls` at the current
cursor row and column. A popup can open another popup with `{ parent: tools }`;
`close()` returns to its parent. `capture()` and `locate()` preserve a control
cursor when surrounding text moves. Hosts own redraws, editable boundaries, and
focus/scroll policy; `focusTarget` identifies the first active choice.
`field(label, value, { multiline })` adds editable text rows to a popup. A host can
use `fieldAt(row)` to find the field and its line index, update its `value`, then
`refresh()`; `capture()`/`locate()` also preserve cursors in those fields. Field
activation falls through to the native text editor rather than closing the popup.
The host owns input handling and keeps these edits separate from its document.
`note(text)`, `setDisabled(boolean)`, and `destroy()` cover status, pending actions,
and disposal. Run `node test-text-controls.js` for component checks.
