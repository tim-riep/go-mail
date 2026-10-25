package shamir

// Arithmetic in GF(2^8) with the AES reduction polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11b), the field also used by OpenBao's shamir
// package.
//
// Timing: shares and polynomial coefficients are secrets. The functions
// below therefore contain no branch and no memory access that depends on
// their operands. mul is a bit-serial carry-less multiplication whose
// conditional additions are done with masks (0x00 or 0xff) derived from
// single bits; inv raises to the power 254 with a fixed chain of
// multiplications; div is a multiplication by the inverse. The usual
// log/exp tables are avoided because a table lookup with a secret index
// can leak the index through the cache. The cost (a few dozen operations
// per multiplication) is irrelevant for 32-byte secrets.

// add adds two field elements. Subtraction is the same operation.
func add(a, b uint8) uint8 { return a ^ b }

// mul multiplies two field elements in constant time.
func mul(a, b uint8) uint8 {
	var r uint8
	for i := 0; i < 8; i++ {
		// Add a * x^i to the result if bit i of b is set. -(x) for an
		// unsigned x in {0, 1} is 0x00 or 0xff.
		r ^= a & -(b & 1)
		// Multiply a by x and reduce if the top bit fell out.
		carry := a >> 7
		a = (a << 1) ^ (0x1b & -carry)
		b >>= 1
	}
	return r
}

// inv returns the multiplicative inverse a^254 of a, and 0 for a == 0 (the
// callers never divide by 0; the function is total so that no input can
// panic).
func inv(a uint8) uint8 {
	b := mul(a, a)   // a^2
	c := mul(a, b)   // a^3
	b = mul(c, c)    // a^6
	b = mul(b, b)    // a^12
	c = mul(b, c)    // a^15
	b = mul(b, b)    // a^24
	b = mul(b, b)    // a^48
	b = mul(b, c)    // a^63
	b = mul(b, b)    // a^126
	b = mul(a, b)    // a^127
	return mul(b, b) // a^254
}

// div returns a / b, and 0 for b == 0.
func div(a, b uint8) uint8 { return mul(a, inv(b)) }

// polynomial over GF(2^8); coeffs[0] is the constant term.
type polynomial struct {
	coeffs []uint8
}

// eval evaluates the polynomial at x with Horner's method. The number of
// steps depends only on the degree, never on the coefficients.
func (p *polynomial) eval(x uint8) uint8 {
	var out uint8
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		out = add(mul(out, x), p.coeffs[i])
	}
	return out
}

// interpolateAtZero returns the constant term of the polynomial through
// the points (xs[i], ys[i]) by Lagrange interpolation. The x coordinates
// are public share indices; only the y values are secret, and they enter
// through constant-time multiplications only.
func interpolateAtZero(xs, ys []uint8) uint8 {
	var result uint8
	for i := range xs {
		basis := uint8(1)
		for j := range xs {
			if i == j {
				continue
			}
			// (0 - x_j) / (x_i - x_j); in characteristic 2, -x = x.
			basis = mul(basis, div(xs[j], add(xs[i], xs[j])))
		}
		result = add(result, mul(ys[i], basis))
	}
	return result
}
