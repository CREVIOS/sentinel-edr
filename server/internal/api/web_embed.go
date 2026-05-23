package api

import (
	"embed"
	"io/fs"
)

// webFS embeds the built console (Vite output copied here by `make build-web`).
// A placeholder index.html keeps the embed valid before the first frontend build.
//
//go:embed all:webdist
var webFSEmbed embed.FS

func embeddedWeb() (fs.FS, error) {
	return fs.Sub(webFSEmbed, "webdist")
}
