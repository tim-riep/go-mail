package envelope

import (
	"bytes"
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
	// Every failure of the output wraps ErrWrite and the writer's own
	// error.
	if _, err := NewWriter(&failingWriter{n: 10, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, nil); !errors.Is(err, boom) || !errors.Is(err, ErrWrite) {
		t.Fatalf("expected ErrWrite and the writer's error, got %v", err)
	}
	// Failure while writing a block: Write reports it, Close repeats it.
	w, err := NewWriter(&failingWriter{n: 1000, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, &SealOptions{Signer: testSigner()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 2*ChunkSize)); !errors.Is(err, boom) || !errors.Is(err, ErrWrite) {
		t.Fatalf("expected ErrWrite and the writer's error, got %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, boom) {
		t.Fatal("writer must stay failed")
	}
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close must report the earlier error, got %v", err)
	}
	// Failure while writing the last block or trailer in Close: the
	// complete file is 468 bytes, the last block ends 132 bytes before
	// its end (trailer element: type byte, length, 127-byte record), so
	// these two limits fail in the block and in the trailer.
	full, _ := Seal(testHeader(KindMail), []Recipient{testRecipient(t)}, []byte("short"), &SealOptions{Signer: testSigner()})
	for _, n := range []int{len(full) - 140, len(full) - 5} {
		w, err := NewWriter(&failingWriter{n: n, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, &SealOptions{Signer: testSigner()})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("short"))
		if err := w.Close(); !errors.Is(err, boom) || !errors.Is(err, ErrWrite) {
			t.Fatalf("n=%d: expected ErrWrite and the writer's error, got %v", n, err)
		}
	}
}

func TestRandomExhaustedAfterNoncePrefix(t *testing.T) {
	seven := make([]byte, 7)
	if _, err := Seal(testHeader(KindMail), []Recipient{testRecipient(t)}, nil, &SealOptions{Rand: bytesReader(seven)}); !errors.Is(err, ErrRandom) {
		t.Fatalf("expected ErrRandom, got %v", err)
	}
}

func TestVerifySignatureExtraTooLong(t *testing.T) {
	f, err := Parse(seal(t, testHeader(KindMeta), []byte("x"), true))
	if err != nil {
		t.Fatal(err)
	}
	pub := ingestKey.Public()
	if err := f.VerifySignature(pub.(edPublicKey), make([]byte, MaxExtraSize+1)); !errors.Is(err, ErrSigner) {
		t.Fatalf("expected ErrSigner, got %v", err)
	}
}

// TestWriterWipesPlaintextOnError: after any failure, and after Close, the
// writer holds no plaintext.
func TestWriterWipesPlaintextOnError(t *testing.T) {
	boom := errors.New("disk full")
	secret := []byte("secret plaintext that must not linger")
	// Size limit exceeded.
	w, _ := NewWriter(&failingWriter{n: 1 << 20, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	w.Write(secret)
	if _, err := w.Write(make([]byte, MaxContentSize)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if w.buf != nil {
		t.Fatal("buffer kept after the size error")
	}
	// Output failure inside Write.
	w, _ = NewWriter(&failingWriter{n: 1000, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	if _, err := w.Write(make([]byte, 2*ChunkSize)); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if w.buf != nil {
		t.Fatal("buffer kept after the output error")
	}
	// Output failure in Close, and the stored-error path of Close.
	w, _ = NewWriter(&failingWriter{n: 320, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	w.Write(secret)
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if w.buf != nil {
		t.Fatal("buffer kept after Close failed")
	}
	w, _ = NewWriter(&failingWriter{n: 1000, err: boom}, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	w.Write(make([]byte, 2*ChunkSize))
	w.buf = append([]byte(nil), secret...)
	w.Close()
	if w.buf != nil {
		t.Fatal("buffer kept on the stored-error path")
	}
	// Success: nothing left either.
	var out bytes.Buffer
	w, _ = NewWriter(&out, testHeader(KindMail), []Recipient{testRecipient(t)}, nil)
	w.Write(secret)
	if err := w.Close(); err != nil || w.buf != nil {
		t.Fatal("buffer kept after a successful Close")
	}
}
