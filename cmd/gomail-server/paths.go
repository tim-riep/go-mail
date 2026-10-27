package main

import "path/filepath"

// isInside reports whether p lies in root or below it; both must be
// absolute and resolved (resolve).
func isInside(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && filepath.IsLocal(rel)
}
