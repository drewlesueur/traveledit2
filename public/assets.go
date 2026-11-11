// Package assets contains the frontend shared by the standalone editor and
// applications embedding TravelEdit. It has no initialization side effects.
package assets

import "embed"

// Files is the minimal text-editor frontend. Hosts can supply another fs.FS
// through editor.Config.Assets to include additional local fonts or assets.
//
//go:embed index.html md52.js text-controls.js login.html
var Files embed.FS
