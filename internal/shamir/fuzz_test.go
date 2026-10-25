package shamir

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzShareFromWords(f *testing.F) {
	shares, _ := Split(testSecret(), 2, 3, bytes.NewReader(make([]byte, 128)))
	for _, s := range shares {
		f.Add(strings.Join(s.Words(), " "))
	}
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		words := strings.Fields(s)
		sh, err := ShareFromWords(words)
		if err != nil {
			if sh != nil {
				t.Fatal("share returned with error")
			}
			return
		}
		if strings.Join(sh.Words(), " ") != strings.Join(words, " ") {
			t.Fatal("accepted words do not round-trip")
		}
	})
}

func FuzzShareFromBytes(f *testing.F) {
	shares, _ := Split(testSecret(), 3, 5, bytes.NewReader(make([]byte, 128)))
	for _, s := range shares {
		f.Add(s.Bytes())
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		sh, err := ShareFromBytes(data)
		if err != nil {
			if sh != nil {
				t.Fatal("share returned with error")
			}
			return
		}
		if !bytes.Equal(sh.Bytes(), data) {
			t.Fatal("accepted bytes do not round-trip")
		}
	})
}

// FuzzCombine feeds arbitrary share sets to Combine: it must never panic
// and must either reject or return exactly SecretSize bytes.
func FuzzCombine(f *testing.F) {
	shares, _ := Split(testSecret(), 2, 3, bytes.NewReader(make([]byte, 128)))
	var seed []byte
	for _, s := range shares {
		seed = append(seed, s.Bytes()...)
	}
	f.Add(seed)
	f.Add(seed[:ShareSize])
	f.Fuzz(func(t *testing.T, data []byte) {
		var set []*Share
		for len(data) >= ShareSize {
			s, err := ShareFromBytes(data[:ShareSize])
			data = data[ShareSize:]
			if err != nil {
				continue
			}
			set = append(set, s)
		}
		got, err := Combine(set)
		if err != nil {
			if got != nil {
				t.Fatal("secret returned with error")
			}
			return
		}
		if len(got) != SecretSize {
			t.Fatal("wrong secret size")
		}
	})
}
