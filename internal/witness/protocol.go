package witness

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// MaxProofHashes bounds a consistency proof: tlog proofs for int64 sizes
// have fewer than 2*63 hashes.
const MaxProofHashes = 128

// MaxProofBody is the read limit of a consistency response.
const MaxProofBody = MaxProofHashes * 45

// FormatProof encodes a consistency proof as the body of
// GET /gomail/log/consistency: one standard base64 hash (with padding)
// per line, each line ending in "\n"; an empty proof is an empty body.
func FormatProof(p tlog.TreeProof) []byte {
	var b bytes.Buffer
	for _, h := range p {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// ParseProof decodes a body written by FormatProof and accepts nothing
// else: no blank lines, no missing final newline, no other encodings of
// a hash, at most MaxProofHashes lines.
func ParseProof(body []byte) (tlog.TreeProof, error) {
	if len(body) > MaxProofBody {
		return nil, fmt.Errorf("%w: proof too long", ErrProtocol)
	}
	if len(body) == 0 {
		return tlog.TreeProof{}, nil
	}
	s := string(body)
	if !strings.HasSuffix(s, "\n") {
		return nil, fmt.Errorf("%w: missing final newline", ErrProtocol)
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) > MaxProofHashes {
		return nil, fmt.Errorf("%w: too many hashes", ErrProtocol)
	}
	p := make(tlog.TreeProof, len(lines))
	for i, l := range lines {
		raw, err := base64.StdEncoding.Strict().DecodeString(l)
		if err != nil || len(raw) != tlog.HashSize || base64.StdEncoding.EncodeToString(raw) != l {
			return nil, fmt.Errorf("%w: malformed hash in line %d", ErrProtocol, i+1)
		}
		copy(p[i][:], raw)
	}
	return p, nil
}
