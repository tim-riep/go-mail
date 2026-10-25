// Command gen writes the test vectors of package shamir into testdata.
// Run it from internal/shamir:
//
//	go run ./testdata/gen
//
// Randomness is injected as a fixed byte sequence (see Split for its
// layout), so the output is reproducible.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tim-riep/go-mail/internal/shamir"
)

type shareVector struct {
	Index uint8  `json:"index"`
	Bytes string `json:"bytes"`
	Words string `json:"words"`
}

type splitVector struct {
	Name      string        `json:"name"`
	Secret    string        `json:"secret"`
	Threshold int           `json:"threshold"`
	Count     int           `json:"count"`
	Random    string        `json:"random"`
	Shares    []shareVector `json:"shares"`
}

func main() {
	out := flag.String("out", "testdata", "output directory")
	flag.Parse()
	var vectors struct {
		Comment string        `json:"comment"`
		Splits  []splitVector `json:"splits"`
	}
	vectors.Comment = "Shamir splits with injected randomness: 2 bytes identifier, then (threshold-1) coefficient bytes per secret byte. Any threshold of the shares reconstructs the secret."
	secret := sha256.Sum256([]byte("gomail/v1/shamir-test-secret"))
	for _, kn := range [][2]int{{3, 5}, {2, 3}} {
		k, n := kn[0], kn[1]
		random := make([]byte, 2+32*(k-1))
		for i := range random {
			random[i] = byte(i*13 + 7)
		}
		shares, err := shamir.Split(secret[:], k, n, bytes.NewReader(random))
		check(err)
		v := splitVector{Name: fmt.Sprintf("%d-of-%d", k, n), Secret: hex.EncodeToString(secret[:]), Threshold: k, Count: n, Random: hex.EncodeToString(random)}
		for _, s := range shares {
			v.Shares = append(v.Shares, shareVector{Index: s.Index, Bytes: hex.EncodeToString(s.Bytes()), Words: strings.Join(s.Words(), " ")})
		}
		vectors.Splits = append(vectors.Splits, v)
	}
	b, err := json.MarshalIndent(vectors, "", " ")
	check(err)
	path := filepath.Join(*out, "vectors.json")
	check(os.WriteFile(path, append(b, '\n'), 0o644))
	fmt.Println("wrote", path)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
