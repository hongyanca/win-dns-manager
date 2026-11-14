// Package asset embeds the images used by the app.
package asset

import _ "embed"

// AppIcon is the PNG used for the window and system tray.
//
//go:embed app-icon.png
var AppIcon []byte
