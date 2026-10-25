package envelope

import (
	"errors"
	"testing"
)

// failingWriter fails after n bytes.
type failingWriter struct {
	n   int
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, w.err
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, w.err
	}
	w.n -= len(p)
	return len(p), nil
}

func TestWriterOutputErrors(t *testing.T) {
	boom := errors.New("disk full")
	// Failure while writing the head.
	if _, err := NewWriter(&failingWriter{n: 10, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, nil); !errors.Is(err, boom) {
		t.Fatalf("expected the writer's error, got %v", err)
	}
	// Failure while writing a block: Write reports it, Close repeats it.
	w, err := NewWriter(&failingWriter{n: 1000, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, &SealOptions{Signer: testSigner()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 2*ChunkSize)); !errors.Is(err, boom) {
		t.Fatalf("expected the writer's error, got %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, boom) {
		t.Fatal("writer must stay failed")
	}
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close must report the earlier error, got %v", err)
	}
	// Failure while writing the last block or trailer in Close: the
	// complete file is 466 bytes, the last block ends 131 bytes before
	// its end, so these two limits fail in the block and in the trailer.
	full, _ := Seal(testHeader(KindMail), []Recipient{testRecipient(t)}, []byte("short"), &SealOptions{Signer: testSigner()})
	for _, n := range []int{len(full) - 140, len(full) - 5} {
		w, err := NewWriter(&failingWriter{n: n, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, &SealOptions{Signer: testSigner()})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("short"))
		if err := w.Close(); !errors.Is(err, boom) {
			t.Fatalf("n=%d: expected the writer's error, got %v", n, err)
		}
	}
}
