package main

import "path/filepath"

func absPath(p string) (string, error) { return filepath.Abs(p) }

func isInside(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && filepath.IsLocal(rel)
}
