package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// readFileLimitedOld29a is ReadFileLimited as it was before backlog 105
// (io.ReadAll over io.LimitReader), the reference for the comparison
// with special files.
func readFileLimitedOld29a(path string, max int64) ([]byte, error) {
	f, fi, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: %s has %d bytes, at most %d", ErrTooLarge, filepath.Base(path), fi.Size(), max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s grew beyond %d bytes", ErrTooLarge, filepath.Base(path), max)
	}
	return data, nil
}

// mult8Reader29a serves n bytes and, as /proc/self/pagemap, fails with
// EINVAL for a read whose count is not a multiple of 8; it records the
// size of the first read.
type mult8Reader29a struct {
	n, first, calls int
}

func (r *mult8Reader29a) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		r.first = len(p)
	}
	if len(p)%8 != 0 {
		return 0, syscall.EINVAL
	}
	if r.n == 0 {
		return 0, io.EOF
	}
	k := min(len(p), r.n)
	r.n -= k
	return k, nil
}

// TestReadAtMostFirstRead (review 28D2, finding 1): with a Stat size of
// zero (or below), the first read asks for min(512, limit) bytes, as
// io.ReadAll does, not for one byte; with a Stat size it asks for
// size+1 bytes, at most limit. A reader that refuses counts that are
// not a multiple of 8 (as /proc/self/pagemap) gives the same result as
// io.ReadAll over io.LimitReader.
func TestReadAtMostFirstRead(t *testing.T) {
	for _, c := range []struct{ size, limit, want int64 }{
		{0, 1, 1}, {0, 8, 8}, {0, 100, 100}, {0, 512, 512}, {0, 513, 512},
		{0, 65537, 512}, {0, 1 << 40, 512}, {-3, 4096, 512},
		{1, 4096, 2}, {5, 4096, 6}, {600, 4096, 601}, {4095, 4096, 4096},
	} {
		r := &mult8Reader29a{}
		if _, err := readAtMost(r, c.size, c.limit); err != nil && !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("%+v: %v", c, err)
		}
		if int64(r.first) != c.want {
			t.Fatalf("size %d, limit %d: first read of %d bytes, want %d", c.size, c.limit, r.first, c.want)
		}
	}
	for _, max := range []int64{7, 15, 511, 1023, 4095, 64 << 10} {
		for _, n := range []int{0, 8, 504, 512, 1 << 20} {
			r1, r2 := &mult8Reader29a{n: n}, &mult8Reader29a{n: n}
			old, oerr := io.ReadAll(io.LimitReader(r1, max+1))
			if oerr != nil {
				old = nil // as ReadFileLimited did
			} else if int64(len(old)) > max {
				old, oerr = nil, ErrTooLarge
			}
			got, err := readAtMost(r2, 0, max+1)
			if err == nil && int64(len(got)) > max {
				got, err = nil, ErrTooLarge
			}
			if !errors.Is(err, oerr) || (err == nil) != (oerr == nil) || len(got) != len(old) {
				t.Fatalf("max %d, %d bytes: %d bytes, %v; io.ReadAll: %d bytes, %v", max, n, len(got), err, len(old), oerr)
			}
		}
	}
}

// TestReadFileLimitedSpecialLikeOld (review 28D2, finding 1): a file of
// the data directory replaced by a link to /proc/self/pagemap (Stat
// size 0, reads must be a multiple of 8) gives the same as before
// backlog 105, for the limits of the callers: on amd64 "grew beyond" or
// EINVAL, on 386 (a pagemap of 8 MiB) also the content. The content
// itself changes from read to read; compared are its length and the
// error.
func TestReadFileLimitedSpecialLikeOld(t *testing.T) {
	const target = "/proc/self/pagemap"
	f, _, err := OpenRegular(target)
	if err != nil {
		t.Skipf("%s cannot be opened as a regular file: %v", target, err)
	}
	f.Close()
	p := filepath.Join(t.TempDir(), "mailbox.rec")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	for _, max := range []int64{
		7, 15, 511, 1023, 4095, MaxInviteFile, MaxWrapFile, MaxRecordFile,
		MaxUserFile, MaxPendingFile, MaxIndexSegmentFile, MaxAddressesFile, MaxMailFile,
	} {
		old, oerr := readFileLimitedOld29a(p, max)
		got, err := ReadFileLimited(p, max)
		t.Logf("max %d: old %d bytes, %v; new %d bytes, %v", max, len(old), oerr, len(got), err)
		if (err == nil) != (oerr == nil) || (err != nil && err.Error() != oerr.Error()) ||
			errors.Is(err, ErrTooLarge) != errors.Is(oerr, ErrTooLarge) || len(got) != len(old) || (got == nil) != (old == nil) {
			t.Errorf("max %d: %d bytes, %v; before backlog 105: %d bytes, %v", max, len(got), err, len(old), oerr)
		}
	}
}

// TestReadFileLimitedGrowthShape (review 28D2, R1; review 29A, R1 and
// finding 3): the worst case of the copy. The Stat size is chosen so
// that the doubling buffer is full just below half the limit, at
// exactly the size the file has at the read: the buffer grows to the
// limit, the read ends there with less than half of it.
//   - Where the doubling started small, the earlier buffers add up to
//     about twice the result; a copy of it made 2.5 times max (28D2).
//     The copy is left out, so the read stays at about twice max.
//   - Where the buffer grew to the limit in one step (a Stat size above
//     a quarter of the limit), the copy fits in twice max and is made,
//     so a caller that keeps the result does not keep the limit
//     (without the copy four times its bytes, review 29A R1).
//
// The bound is twice max plus 24 KiB (as in
// TestReadFileLimitedGrowthAllocates; 64 KiB before review 29A), so
// that at MaxRecordFile, too, a copy as in 28D2 fails it. TotalAlloc of
// the whole process: this test, as all allocation tests of the
// package, must not run in parallel with other tests.
func TestReadFileLimitedGrowthShape(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "shape")
	for _, c := range []struct {
		max, stat, read int64
		copied          bool
	}{
		{MaxMailFile, 51236, 26233344, false},
		{MaxPendingFile, 65534, 1048560, false},
		{MaxRecordFile, 510, 32704, false},
		{MaxMailFile, 13116781, 13116782, true},
		{MaxPendingFile, 524288, 524289, true},
		{MaxRecordFile, 32766, 32767, true},
	} {
		// The shape: read is the last buffer size of the doubling
		// from stat+1 that is not above half the limit.
		limit := c.max + 1
		last := c.stat + 1
		for 2*last <= limit/2 {
			last *= 2
		}
		if last != c.read || c.read >= limit/2 {
			t.Fatalf("%+v: the doubling ends at %d, not at the size read", c, last)
		}
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
		data, err := ReadFileLimited(p, c.max)
		runtime.ReadMemStats(&after)
		readLimitedHook = nil
		if err != nil || int64(len(data)) != c.read {
			t.Fatalf("%+v: %d bytes, %v", c, len(data), err)
		}
		got := after.TotalAlloc - before.TotalAlloc
		t.Logf("%+v: allocated %d bytes (%.3f times max, %d above twice max), buffer of %d bytes",
			c, got, float64(got)/float64(c.max), int64(got)-2*c.max, cap(data))
		if got > uint64(2*c.max+24<<10) {
			t.Errorf("%+v: allocated %d bytes (%.3f times max), more than twice max", c, got, float64(got)/float64(c.max))
		}
		if c.copied && int64(cap(data)) > c.read+c.read/8+8192 {
			t.Errorf("%+v: %d bytes in a buffer of %d, not copied", c, len(data), cap(data))
		}
		if !c.copied && int64(cap(data)) != limit {
			t.Errorf("%+v: %d bytes in a buffer of %d, want the buffer of the limit", c, len(data), cap(data))
		}
	}
}

// bufTrack29a serves n bytes and fills every buffer it gets. It
// records the size of each buffer of readAtMost (pos + cap(p): the
// buffer is filled from its start and grows only when full), so the
// sum of the buffers is known without measuring the heap.
type bufTrack29a struct {
	n, pos int64
	caps   []int64
}

func (r *bufTrack29a) Read(p []byte) (int, error) {
	if c := r.pos + int64(cap(p)); len(r.caps) == 0 || c != r.caps[len(r.caps)-1] {
		r.caps = append(r.caps, c)
	}
	if len(p) == 0 {
		return 0, errEmptyRead29a
	}
	if r.pos == r.n {
		return 0, io.EOF
	}
	k := min(int64(len(p)), r.n-r.pos)
	r.pos += k
	return int(k), nil
}

// TestReadAtMostCopyBound (review 29A, R1): the rule of the copy for
// every shape of growth. A result with more than 4 KiB and more than
// half of its buffer unused is copied if and only if the buffers and
// the copy add up to at most twice limit; so the sum never exceeds
// twice limit, and a result that is not copied holds less than three
// times its bytes. A buffer that did not grow, or grew to limit in one
// step, is always copied then. The Stat sizes and final sizes are the
// ones of the doubling chains (around each buffer size, a quarter, a
// third and half of the limit), as in the model of the review; limit
// 1000065 has a shape at exactly twice limit (Stat 200012: buffers of
// 200013, 400026 and limit, 400026 bytes).
func TestReadAtMostCopyBound(t *testing.T) {
	for _, limit := range []int64{16385, 65537, 1000065} {
		sizes := []int64{0, 1, 255, 341, 342, 343, 348, 510, 511, 683, 1023, 4095, 200012,
			limit / 8, limit/4 - 1, limit / 4, limit/4 + 1, limit / 3, limit/3 + 1, limit/2 - 2, limit / 2, limit - 2, limit - 1}
		worst, worstDesc := 0.0, ""
		for _, s := range sizes {
			if s >= limit {
				continue
			}
			ns := map[int64]bool{0: true, s: true, s + 1: true, s + 2: true, limit / 4: true, limit/3 + 1: true,
				limit/2 - 1: true, limit / 2: true, limit - 1: true, limit: true, limit + 1: true}
			c := min(max(s+1, 1), limit)
			if s <= 0 {
				c = min(512, limit)
			}
			for c < limit {
				ns[c-1], ns[c], ns[c+1] = true, true, true
				c = max(2*c, 512)
				if c > limit/2 {
					c = limit
				}
			}
			for n := range ns {
				if n < 0 {
					continue
				}
				r := &bufTrack29a{n: n}
				got, err := readAtMost(r, s, limit)
				desc := fmt.Sprintf("limit %d, size %d, %d bytes, buffers %v", limit, s, n, r.caps)
				if err != nil || int64(len(got)) != min(n, limit) {
					t.Fatalf("%s: %d bytes, %v", desc, len(got), err)
				}
				sum := int64(0)
				for _, b := range r.caps {
					sum += b
				}
				last, l := r.caps[len(r.caps)-1], int64(len(got))
				copied := int64(cap(got)) != last
				want := last-l > 4096 && l < last/2 && sum+l <= 2*limit
				if copied != want {
					t.Fatalf("%s: copied %t, want %t (sum of buffers %d, twice limit %d)", desc, copied, want, sum, 2*limit)
				}
				if copied {
					sum += l
				}
				if sum > 2*limit {
					t.Fatalf("%s: buffers and copy add up to %d, more than twice limit", desc, sum)
				}
				if k := int64(cap(got)); k-l > 4096 {
					if k >= 3*l {
						t.Fatalf("%s: %d bytes kept in a buffer of %d", desc, l, k)
					}
					if f := float64(k) / float64(l); f > worst {
						worst, worstDesc = f, desc
					}
				}
			}
		}
		t.Logf("limit %d: largest buffer for its bytes (more than 4 KiB unused) %.2f times, at %s", limit, worst, worstDesc)
	}
}
