//go:build !darwin

package main

// PreviewPath falls back to OpenPath on platforms without Quick Look.
func (p *platform) PreviewPath(path string) error {
	return p.OpenPath(path)
}
