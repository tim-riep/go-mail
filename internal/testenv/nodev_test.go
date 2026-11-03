//go:build !gomail_dev

package testenv

import "testing"

// TestSkipWithoutDev: a build without the tag gomail_dev has no
// development ceremony; New, NewLogged and RequireDev skip the test
// instead of failing it (task 15b point 4).
func TestSkipWithoutDev(t *testing.T) {
	for name, fn := range map[string]func(testing.TB){
		"New":        func(tb testing.TB) { New(tb) },
		"NewLogged":  func(tb testing.TB) { NewLogged(tb) },
		"RequireDev": RequireDev,
	} {
		skipped, returned := false, false
		t.Run(name, func(t *testing.T) {
			defer func() { skipped = t.Skipped() }()
			fn(t)
			returned = true
		})
		if !skipped || returned {
			t.Fatalf("%s: skipped %v, returned %v", name, skipped, returned)
		}
	}
}
