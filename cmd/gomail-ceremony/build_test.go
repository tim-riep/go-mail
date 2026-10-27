package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestProductionBuild: the program built without tags contains no path
// that writes a platform root into a file (task 15b point 4): neither
// the text of the root file of the development ceremony nor its file
// name nor the accepting placeholder log translogtest; the build with
// the tag gomail_dev contains them (a check that the strings searched
// for are the right ones).
func TestProductionBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the program twice")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the program:", err)
	}
	dir := t.TempDir()
	marks := [][]byte{[]byte("INSECURE - DEVELOPMENT ONLY"), []byte("platform-root.INSECURE-DEV-ONLY.txt")}
	for _, c := range []struct {
		tags string
		dev  bool
	}{{"", false}, {"gomail_dev", true}} {
		bin := filepath.Join(dir, "gomail-ceremony-"+c.tags)
		args := []string{"build", "-o", bin}
		if c.tags != "" {
			args = append(args, "-tags", c.tags)
		}
		build := exec.Command(goBin, append(args, ".")...)
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %q: %v\n%s", c.tags, err, out)
		}
		b, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range marks {
			if bytes.Contains(b, m) != c.dev {
				t.Fatalf("build %q: %q contained %v", c.tags, m, !c.dev)
			}
		}
		if c.tags == "" && bytes.Contains(b, []byte("internal/translog/translogtest")) {
			t.Fatal("production build contains translogtest")
		}
	}
}
