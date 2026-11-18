package store

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// writeFile28d writes data to a new file named name in dir.
func writeFile28d(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hook28d sets readLimitedHook to fn for the test.
func hook28d(t *testing.T, fn func(path string)) {
	t.Helper()
	readLimitedHook = fn
	t.Cleanup(func() { readLimitedHook = nil })
}

// The two tests on readAtMost with a reader that refuses an empty
// buffer stand before the tests of this file that read a real file
// (review 28D2, finding 2): should the loop of readAtMost pass an empty
// buffer to Read again, an os.File answers (0, nil) and those tests
// would hang until the timeout; these two fail at once, so the FAIL is
// in the output before the hang (and with -failfast there is no hang).
// That holds for the source order only: with -shuffle a file test may
// run first and hang without a FAIL before it (review 29A, finding 5).

// errEmptyRead29a is returned by noEmptyRead29a for an empty buffer.
var errEmptyRead29a = errors.New("read into an empty buffer")

// noEmptyRead29a serves n bytes, in pieces of at most chunk bytes when
// chunk > 0. A read into an empty buffer fails at once: an os.File
// answers it with (0, nil), and readAtMost would read again without
// end. It also fails a buffer that reaches beyond limit (pos + cap(p):
// the buffer is filled from its start, so this is its size).
type noEmptyRead29a struct {
	n, pos, chunk    int
	limit            int64
	empty, oversized bool
}

func (r *noEmptyRead29a) Read(p []byte) (int, error) {
	if len(p) == 0 {
		r.empty = true
		return 0, errEmptyRead29a
	}
	if int64(r.pos+cap(p)) > r.limit {
		r.oversized = true
		return 0, fmt.Errorf("buffer of %d bytes for a limit of %d", r.pos+cap(p), r.limit)
	}
	if r.pos == r.n {
		return 0, io.EOF
	}
	k := min(len(p), r.n-r.pos)
	if r.chunk > 0 {
		k = min(k, r.chunk)
	}
	r.pos += k
	return k, nil
}

// TestReadAtMostNoEmptyRead (review 28D2, finding 2): readAtMost never
// passes an empty buffer to Read and never a buffer larger than limit,
// at the limit, one byte below and above it and after growing. A
// change that brings back an endless loop (the loop up to limit
// inclusive, the jump to limit-1) fails here at once, not by the
// timeout.
func TestReadAtMostNoEmptyRead(t *testing.T) {
	for _, limit := range []int64{1, 2, 511, 512, 513, 1024, 1025, 4097, 65537} {
		for _, size := range []int64{0, 1, limit / 3, limit - 1} {
			for _, n := range []int64{0, limit - 1, limit, limit + 1, 3 * limit} {
				for _, chunk := range []int{0, 7} {
					r := &noEmptyRead29a{n: int(max(n, 0)), chunk: chunk, limit: limit}
					got, err := readAtMost(r, size, limit)
					desc := fmt.Sprintf("limit %d, size %d, %d bytes, pieces of %d", limit, size, n, chunk)
					if r.empty || r.oversized || err != nil {
						t.Fatalf("%s: empty read %t, buffer above limit %t, %v", desc, r.empty, r.oversized, err)
					}
					if want := min(n, limit); int64(len(got)) != want || int64(cap(got)) > limit {
						t.Fatalf("%s: %d bytes in a buffer of %d, want %d", desc, len(got), cap(got), want)
					}
				}
			}
		}
	}
}

// TestReadAtMostCapFull (review 28D2, finding 3): when the buffer is
// full at the largest size it may have (math.MaxInt, only reachable on
// 386 with a limit of 2 GiB or more; here a smaller cap) before limit,
// readAtMost ends with ErrTooLarge and nil instead of passing an empty
// buffer to Read. Below that cap the data is read as usual, also when
// the Stat size is above it. The message is fixed, without content,
// and true also for a file of exactly maxCap bytes, whose end was not
// seen (review 29A, finding 2): not "more than N bytes". That readAtMost
// passes math.MaxInt as the cap is not tested: on 64 bit it shows only
// with a buffer above 2 GiB (review 29A, finding 4).
func TestReadAtMostCapFull(t *testing.T) {
	const maxCap = 4096
	const msg = "store: file too large: the buffer is full at 4096 bytes before the limit"
	for _, c := range []struct{ size, n int64 }{{0, 10000}, {0, maxCap}, {3, 10000}, {1 << 20, 10000}} {
		r := &noEmptyRead29a{n: int(c.n), limit: 1 << 30}
		got, err := readAtMostCap(r, c.size, 10000, maxCap)
		if !errors.Is(err, ErrTooLarge) || got != nil || r.empty {
			t.Fatalf("%+v: %d bytes (nil %t), %v, empty read %t; want nil and ErrTooLarge", c, len(got), got == nil, err, r.empty)
		}
		if err.Error() != msg {
			t.Fatalf("%+v: message %q, want %q", c, err, msg)
		}
		if r.pos != maxCap {
			t.Fatalf("%+v: %d bytes read before ErrTooLarge, want %d", c, r.pos, maxCap)
		}
	}
	for _, c := range []struct{ size, n int64 }{{0, 3000}, {1 << 20, 3000}, {0, maxCap - 1}} {
		r := &noEmptyRead29a{n: int(c.n), limit: maxCap}
		got, err := readAtMostCap(r, c.size, 10000, maxCap)
		if err != nil || int64(len(got)) != c.n || r.empty || r.oversized {
			t.Fatalf("%+v: %d bytes, %v, empty read %t, buffer above the cap %t", c, len(got), err, r.empty, r.oversized)
		}
	}
}

// TestReadFileLimitedBounds (backlog 105): a file of exactly max bytes
// is read whole; one of max+1 bytes is refused by the size from Stat,
// with the message "has N bytes, at most M", before anything is read.
func TestReadFileLimitedBounds(t *testing.T) {
	dir := t.TempDir()
	for _, max := range []int64{1, 7, 4096, 64 << 10} {
		data := bytes.Repeat([]byte{'x'}, int(max))
		data[0], data[len(data)-1] = 'a', 'z'
		p := writeFile28d(t, dir, fmt.Sprintf("exact-%d", max), data)
		got, err := ReadFileLimited(p, max)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("max %d, file of max bytes: %d bytes, %v", max, len(got), err)
		}
		p = writeFile28d(t, dir, fmt.Sprintf("over-%d", max), append(data, '!'))
		read := false
		hook28d(t, func(string) { read = true })
		got, err = ReadFileLimited(p, max)
		want := fmt.Sprintf("store: file too large: over-%d has %d bytes, at most %d", max, max+1, max)
		if !errors.Is(err, ErrTooLarge) || err.Error() != want || got != nil {
			t.Fatalf("max %d, file of max+1 bytes: %d bytes, %v; want %q", max, len(got), err, want)
		}
		if read {
			t.Fatalf("max %d: a file above the limit was read", max)
		}
		readLimitedHook = nil
	}
}

// TestReadFileLimitedGrows (backlog 105): a file that grows between
// Stat and the read is read in full while it stays within max (the
// buffer of Stat size+1 grows), and is refused with "grew beyond" once
// it has more than max bytes, also when it grows by a single byte to
// max+1.
func TestReadFileLimitedGrows(t *testing.T) {
	dir := t.TempDir()
	const max = 64 << 10
	for _, c := range []struct {
		name        string
		start, grow int
		tooLarge    bool
	}{
		{"by one byte", 100, 1, false},
		{"to the limit", 100, max - 100, false},
		{"from one below to the limit", max - 1, 1, false},
		{"from the limit to limit+1", max, 1, true},
		{"from small beyond the limit", 100, max, true},
		{"far beyond the limit", max / 2, 4 * max, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			start := bytes.Repeat([]byte{'s'}, c.start)
			more := bytes.Repeat([]byte{'g'}, c.grow)
			more[len(more)-1] = 'e'
			p := writeFile28d(t, dir, "grow", start)
			hook28d(t, func(path string) {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := f.Write(more); err != nil {
					t.Error(err)
				}
				f.Close()
			})
			got, err := ReadFileLimited(p, max)
			if c.tooLarge {
				want := fmt.Sprintf("store: file too large: grow grew beyond %d bytes", max)
				if !errors.Is(err, ErrTooLarge) || err.Error() != want || got != nil {
					t.Fatalf("%d bytes, %v; want %q", len(got), err, want)
				}
				return
			}
			if err != nil || !bytes.Equal(got, append(start, more...)) {
				t.Fatalf("%d bytes (want %d), %v", len(got), c.start+c.grow, err)
			}
		})
	}
}

// TestReadFileLimitedShrinks (backlog 105): a file that shrinks between
// Stat and the read is returned with the bytes it has at the read, no
// error and no padding from the buffer allocated for the Stat size.
func TestReadFileLimitedShrinks(t *testing.T) {
	dir := t.TempDir()
	const max = 64 << 10
	for _, to := range []int64{0, 1, 4096, max - 1} {
		data := bytes.Repeat([]byte{'k'}, max)
		p := writeFile28d(t, dir, fmt.Sprintf("shrink-%d", to), data)
		hook28d(t, func(path string) {
			if err := os.Truncate(path, to); err != nil {
				t.Error(err)
			}
		})
		got, err := ReadFileLimited(p, max)
		if err != nil || !bytes.Equal(got, data[:to]) {
			t.Fatalf("shrunk to %d: %d bytes, %v", to, len(got), err)
		}
	}
}

// TestReadFileLimitedEmpty (backlog 105): an empty file is read as an
// empty, non-nil slice (as io.ReadAll returned it), also with max 0;
// an empty file that has bytes by the time of the read (as a file whose
// Stat shows no size) is read in full, not skipped by its Stat size.
func TestReadFileLimitedEmpty(t *testing.T) {
	dir := t.TempDir()
	p := writeFile28d(t, dir, "empty", nil)
	for _, max := range []int64{0, 1, MaxRecordFile} {
		got, err := ReadFileLimited(p, max)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("max %d: %v (nil %t), %v", max, got, got == nil, err)
		}
	}
	hook28d(t, func(path string) {
		if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
			t.Error(err)
		}
	})
	if got, err := ReadFileLimited(p, MaxRecordFile); err != nil || string(got) != "abc" {
		t.Fatalf("empty at Stat, three bytes at the read: %q, %v", got, err)
	}
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFileLimited(p, 2); !errors.Is(err, ErrTooLarge) || got != nil {
		t.Fatalf("empty at Stat, three bytes at the read, max 2: %q, %v", got, err)
	}
}

// TestReadFileLimitedAllocates (backlog 105): reading a file of n bytes
// that keeps its size allocates about n bytes once, not about 2.2 n as
// io.ReadAll over io.LimitReader did (a mail file of 50 MiB: about
// 112 MiB). The file is sparse; the bound leaves room for the open and
// the error paths, not for a second buffer.
//
// The allocation tests of this file and fs29a_test.go measure
// TotalAlloc of the whole process: they must not run in parallel (no
// t.Parallel here or in another test of the package), or the
// allocations of the other test count against the bound (review 28D2,
// finding 4).
func TestReadFileLimitedAllocates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sparse")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	const size = 8 << 20
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, max := range []int64{size, MaxMailFile} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		data, err := ReadFileLimited(p, max)
		runtime.ReadMemStats(&after)
		if err != nil || len(data) != size {
			t.Fatalf("max %d: %d bytes, %v", max, len(data), err)
		}
		if got := after.TotalAlloc - before.TotalAlloc; got > size+size/8 {
			t.Fatalf("max %d: reading %d bytes allocated %d bytes (%.2f times the size)", max, size, got, float64(got)/size)
		}
		if cap(data) > size+4096 {
			t.Fatalf("max %d: buffer of %d bytes for a file of %d", max, cap(data), size)
		}
	}
}

// TestReadFileLimitedReadError (review 28D, finding 1): a read error is
// returned as is, with no bytes, not taken for the end of the file.
// /proc/self/pagemap is a regular file with Stat size 0 whose read
// fails with EINVAL for a count that is not a multiple of 8.
func TestReadFileLimitedReadError(t *testing.T) {
	const p = "/proc/self/pagemap"
	f, _, err := OpenRegular(p)
	if err != nil {
		t.Skipf("%s cannot be opened as a regular file: %v", p, err)
	}
	f.Close()
	got, err := ReadFileLimited(p, 4096)
	if !errors.Is(err, syscall.EINVAL) || got != nil {
		t.Fatalf("%d bytes (nil %t), %v; want nil and EINVAL", len(got), got == nil, err)
	}
}

// failAfter28d serves n bytes, then fails with err; it counts its calls.
type failAfter28d struct {
	n, calls int
	err      error
}

func (r *failAfter28d) Read(p []byte) (int, error) {
	r.calls++
	if r.n == 0 {
		return 0, r.err
	}
	k := min(len(p), r.n)
	r.n -= k
	return k, nil
}

// TestReadAtMostReadError (review 28D, finding 1): readAtMost returns a
// read error with nil, before or after bytes were read, within the
// buffer of the Stat size or after it grew; an error after limit bytes
// is not seen, as with io.LimitReader.
func TestReadAtMostReadError(t *testing.T) {
	e := errors.New("read failed")
	for _, c := range []struct{ size, n, limit int64 }{
		{0, 0, 10}, {5, 5, 10}, {5, 3, 10}, {0, 9, 10}, {3, 9000, 10000},
	} {
		got, err := readAtMost(&failAfter28d{n: int(c.n), err: e}, c.size, c.limit)
		if err != e || got != nil {
			t.Fatalf("%+v: %d bytes (nil %t), %v", c, len(got), got == nil, err)
		}
	}
	got, err := readAtMost(&failAfter28d{n: 10, err: e}, 3, 10)
	want, werr := io.ReadAll(io.LimitReader(&failAfter28d{n: 10, err: e}, 10))
	if err != werr || !bytes.Equal(got, want) || len(got) != 10 {
		t.Fatalf("error after the limit: %d bytes, %v; io.ReadAll: %d bytes, %v", len(got), err, len(want), werr)
	}
}

// TestReadFileLimitedLimitOverflow (review 28D, finding 2) records the
// behaviour for limits no caller uses, unchanged by backlog 105: with
// max = MaxInt64, max+1 overflows and nothing is read; the result is an
// empty, non-nil slice without error (io.LimitReader with N < 0). A max
// below zero is refused by the size from Stat, also for an empty file.
// readAtMost itself returns an empty, non-nil slice for a limit of zero
// or less and does not read.
func TestReadFileLimitedLimitOverflow(t *testing.T) {
	dir := t.TempDir()
	p := writeFile28d(t, dir, "f", []byte("abc"))
	read := false
	hook28d(t, func(string) { read = true })
	got, err := ReadFileLimited(p, math.MaxInt64)
	if err != nil || got == nil || len(got) != 0 || !read {
		t.Fatalf("max MaxInt64: %q (nil %t), %v, hook called %t", got, got == nil, err, read)
	}
	readLimitedHook = nil
	empty := writeFile28d(t, dir, "e", nil)
	for _, max := range []int64{-1, math.MinInt64} {
		for _, c := range []struct {
			path string
			size int
		}{{p, 3}, {empty, 0}} {
			got, err := ReadFileLimited(c.path, max)
			want := fmt.Sprintf("store: file too large: %s has %d bytes, at most %d", filepath.Base(c.path), c.size, max)
			if !errors.Is(err, ErrTooLarge) || err.Error() != want || got != nil {
				t.Fatalf("max %d, %d bytes: %q, %v; want %q", max, c.size, got, err, want)
			}
		}
	}
	for _, limit := range []int64{0, -1, math.MinInt64} {
		r := &failAfter28d{n: 3, err: io.EOF}
		got, err := readAtMost(r, 3, limit)
		if err != nil || got == nil || len(got) != 0 || r.calls != 0 {
			t.Fatalf("limit %d: %q (nil %t), %v, %d reads", limit, got, got == nil, err, r.calls)
		}
	}
}

// TestReadFileLimitedGrowthAllocates (review 28D, F1): a file that
// grows between Stat and the read (here also from 0 bytes, as a file of
// /proc shows) allocates at most about twice max in all (the bound adds
// 24 KiB: up to 16 KiB for two large buffers rounded up to whole pages
// of 8 KiB, the rest for the open and the error paths; 64 KiB before
// review 29A, finding 3), not up to six times as when the buffer grew
// as append does: the buffer doubles up to max+1 and never holds more
// than max+1 bytes. The limits include powers of two,
// where the byte that shows the end of the file would otherwise need
// one more buffer, and one just above a power of two. TotalAlloc of the
// whole process: not in parallel (see TestReadFileLimitedAllocates).
func TestReadFileLimitedGrowthAllocates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "grow")
	for _, max := range []int64{MaxRecordFile, 1<<20 + 100, MaxPendingFile, MaxMailFile} {
		for _, c := range []struct{ stat, read int64 }{
			{0, max}, {0, 10 * max}, {max / 4, max}, {max - 1, max},
		} {
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(c.stat); err != nil {
				t.Fatal(err)
			}
			f.Close()
			hook28d(t, func(path string) {
				if err := os.Truncate(path, c.read); err != nil {
					t.Error(err)
				}
			})
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			data, err := ReadFileLimited(p, max)
			runtime.ReadMemStats(&after)
			readLimitedHook = nil
			if c.read > max {
				if !errors.Is(err, ErrTooLarge) || data != nil {
					t.Fatalf("max %d, %d -> %d bytes: %d bytes, %v; want ErrTooLarge", max, c.stat, c.read, len(data), err)
				}
			} else if err != nil || int64(len(data)) != c.read {
				t.Fatalf("max %d, %d -> %d bytes: %d bytes, %v", max, c.stat, c.read, len(data), err)
			}
			got := after.TotalAlloc - before.TotalAlloc
			t.Logf("max %d, %d -> %d bytes: allocated %d bytes (%.2f times max)", max, c.stat, c.read, got, float64(got)/float64(max))
			if got > uint64(2*max+24<<10) {
				t.Fatalf("max %d, %d -> %d bytes: allocated %d bytes (%.2f times max)", max, c.stat, c.read, got, float64(got)/float64(max))
			}
			if int64(cap(data)) > max+1 {
				t.Fatalf("max %d, %d -> %d bytes: buffer of %d bytes", max, c.stat, c.read, cap(data))
			}
		}
	}
}

// TestReadFileLimitedShrunkCopied (review 28D, F2): a file that shrinks
// between Stat and the read is returned in a buffer of about its new
// size, not in the one allocated for the Stat size, so a caller that
// keeps the result does not keep up to max+1 bytes; an empty result
// stays non-nil. HeapAlloc of the whole process: not in parallel (see
// TestReadFileLimitedAllocates).
func TestReadFileLimitedShrunkCopied(t *testing.T) {
	dir := t.TempDir()
	const max = 2 << 20
	for _, to := range []int64{0, 10, 4096, max / 8, max/4 - 1} {
		p := writeFile28d(t, dir, fmt.Sprintf("shrink-%d", to), bytes.Repeat([]byte{'k'}, 1<<20))
		hook28d(t, func(path string) {
			if err := os.Truncate(path, to); err != nil {
				t.Error(err)
			}
		})
		got, err := ReadFileLimited(p, max)
		readLimitedHook = nil
		if err != nil || got == nil || int64(len(got)) != to {
			t.Fatalf("shrunk to %d: %d bytes (nil %t), %v", to, len(got), got == nil, err)
		}
		if cap(got)-len(got) > 4096 && len(got) < cap(got)/2 {
			t.Fatalf("shrunk to %d: %d bytes in a buffer of %d", to, len(got), cap(got))
		}
	}
	// The kept result holds only about its bytes, not the buffer of
	// the Stat size (not only a smaller cap over the same array).
	p := writeFile28d(t, dir, "kept", bytes.Repeat([]byte{'k'}, 1<<20))
	hook28d(t, func(path string) {
		if err := os.Truncate(path, 10); err != nil {
			t.Error(err)
		}
	})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := ReadFileLimited(p, max)
	runtime.GC()
	runtime.ReadMemStats(&after)
	readLimitedHook = nil
	if err != nil || len(got) != 10 {
		t.Fatalf("shrunk to 10: %d bytes, %v", len(got), err)
	}
	if kept := int64(after.HeapAlloc) - int64(before.HeapAlloc); kept > 256<<10 {
		t.Fatalf("shrunk to 10: the result keeps %d bytes of heap", kept)
	}
	runtime.KeepAlive(got)
}
