package shamir

import "testing"

// Reference implementation of GF(256) with the AES polynomial 0x11b,
// using log/exp tables. Tables are fine in tests; they are exactly what
// the production code must not use.
var (
	refExp [512]uint8
	refLog [256]uint8
)

func init() {
	x := uint8(1)
	for i := 0; i < 255; i++ {
		refExp[i] = x
		refLog[x] = uint8(i)
		// multiply x by the generator 3 (= x + 1)
		x2 := x << 1
		if x&0x80 != 0 {
			x2 ^= 0x1b
		}
		x = x2 ^ x
	}
	for i := 255; i < 512; i++ {
		refExp[i] = refExp[i-255]
	}
}

func refMul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}
	return refExp[int(refLog[a])+int(refLog[b])]
}

func refInv(a uint8) uint8 {
	if a == 0 {
		return 0
	}
	return refExp[255-int(refLog[a])]
}

func TestFieldMulExhaustive(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := mul(uint8(a), uint8(b)), refMul(uint8(a), uint8(b)); got != want {
				t.Fatalf("mul(%d, %d) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestFieldInverseExhaustive(t *testing.T) {
	if inv(0) != 0 {
		t.Fatal("inv(0) must be 0 (never used; keeps the function total)")
	}
	for a := 1; a < 256; a++ {
		i := inv(uint8(a))
		if i != refInv(uint8(a)) {
			t.Fatalf("inv(%d) = %d, want %d", a, i, refInv(uint8(a)))
		}
		if mul(uint8(a), i) != 1 {
			t.Fatalf("%d * inv(%d) != 1", a, a)
		}
	}
}

func TestFieldDiv(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 1; b < 256; b++ {
			q := div(uint8(a), uint8(b))
			if mul(q, uint8(b)) != uint8(a) {
				t.Fatalf("div(%d, %d) = %d does not multiply back", a, b, q)
			}
		}
	}
	if div(5, 0) != 0 {
		t.Fatal("division by zero must yield 0, not panic; callers never pass 0")
	}
}

func TestFieldLaws(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			x, y := uint8(a), uint8(b)
			if mul(x, y) != mul(y, x) {
				t.Fatal("not commutative")
			}
			if add(x, y) != x^y {
				t.Fatal("addition is XOR")
			}
			if mul(x, add(y, 1)) != add(mul(x, y), x) {
				t.Fatal("not distributive")
			}
		}
	}
}

func TestPolynomial(t *testing.T) {
	// p(x) = 7 + 3x + 5x^2 over GF(256), evaluated by Horner.
	p := polynomial{coeffs: []uint8{7, 3, 5}}
	for x := 1; x < 256; x++ {
		xx := uint8(x)
		want := add(add(7, mul(3, xx)), mul(5, mul(xx, xx)))
		if got := p.eval(xx); got != want {
			t.Fatalf("eval(%d) = %d, want %d", x, got, want)
		}
	}
	if p.eval(0) != 7 {
		t.Fatal("eval(0) must be the constant term")
	}
}

func TestInterpolate(t *testing.T) {
	// Any k points of a degree k-1 polynomial give back the constant term.
	p := polynomial{coeffs: []uint8{0xaa, 0x01, 0x80, 0xff}}
	xs := []uint8{1, 2, 3, 4, 5, 6}
	ys := make([]uint8, len(xs))
	for i, x := range xs {
		ys[i] = p.eval(x)
	}
	for _, sel := range [][]int{{0, 1, 2, 3}, {2, 3, 4, 5}, {0, 2, 4, 5}, {0, 1, 2, 3, 4, 5}} {
		var sx, sy []uint8
		for _, i := range sel {
			sx = append(sx, xs[i])
			sy = append(sy, ys[i])
		}
		if got := interpolateAtZero(sx, sy); got != 0xaa {
			t.Fatalf("interpolation of %v = %d, want 0xaa", sel, got)
		}
	}
	// Three points of a degree-3 polynomial do not.
	if got := interpolateAtZero(xs[:3], ys[:3]); got == 0xaa {
		t.Fatal("too few points must not reveal the constant term")
	}
}
