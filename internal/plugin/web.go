package plugin

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed web/index.html
var adminUI embed.FS

// serveAdminUI returns the embedded SPA HTML, or nil if path is not the UI.
func serveAdminUI(path string) ([]byte, error) {
	// Normalize to the path under /manager-key-pro
	for _, prefix := range []string{
		"/v0/resource/plugins/manager-key-pro",
		"/v0/management/plugins/manager-key-pro",
	} {
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			break
		}
	}
	if path == "" || path == "/" || path == "/index.html" {
		data, err := adminUI.ReadFile("web/index.html")
		if err != nil {
			return nil, fmt.Errorf("read admin UI: %w", err)
		}
		return data, nil
	}
	return nil, nil
}
