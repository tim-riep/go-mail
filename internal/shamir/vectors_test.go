package shamir

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Splits []struct {
			Name      string
			Secret    string
			Threshold int
			Count     int
			Random    string
			Shares    []struct {
				Index uint8
				Bytes string
				Words string
			}
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Splits) < 2 {
		t.Fatal("expected at least two splits")
	}
	for _, sp := range v.Splits {
		t.Run(sp.Name, func(t *testing.T) {
			secret, _ := hex.DecodeString(sp.Secret)
			random, _ := hex.DecodeString(sp.Random)
			shares, err := Split(secret, sp.Threshold, sp.Count, bytes.NewReader(random))
			if err != nil {
				t.Fatal(err)
			}
			if len(shares) != len(sp.Shares) {
				t.Fatal("share count differs")
			}
			var parsed []*Share
			for i, want := range sp.Shares {
				if got := hex.EncodeToString(shares[i].Bytes()); got != want.Bytes {
					t.Fatalf("share %d bytes differ:\n got %s\nwant %s", i, got, want.Bytes)
				}
				if got := strings.Join(shares[i].Words(), " "); got != want.Words {
					t.Fatalf("share %d words differ", i)
				}
				s, err := ShareFromWords(strings.Fields(want.Words))
				if err != nil {
					t.Fatal(err)
				}
				if s.Index != want.Index {
					t.Fatal("index differs")
				}
				parsed = append(parsed, s)
			}
			got, err := Combine(parsed[len(parsed)-sp.Threshold:])
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("combination from vector words failed: %v", err)
			}
		})
	}
}
