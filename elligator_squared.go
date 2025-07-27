package elligator

import (
	"errors"
	"io"
)

var (
	// ErrInvalidEncoding is returned when the given encoded point is malformed.
	ErrInvalidEncoding = errors.New("elligator: invalid encoding")
	// ErrInvalidPoint is returned when the given point is not an uncompressed SEC point.
	ErrInvalidPoint = errors.New("elligator: invalid point")
)

// Decode maps the Elligator Squared-encoded point to an uncompressed SEC-encoded point.
func Decode(b []byte) ([]byte, error) {
	if len(b) != 64 {
		return nil, ErrInvalidEncoding
	}

	// p = f(u) + f(v)
	u, v := new(fieldElement).SetBytes(b[:32]), new(fieldElement).SetBytes(b[32:])
	x1, y1 := f(u)
	x2, y2 := f(v)
	x3, y3 := p256Add(x1, y1, x2, y2)

	var out [65]byte
	out[0] = 4
	copy(out[1:33], x3.Bytes())
	copy(out[33:], y3.Bytes())
	return out[:], nil
}

// Encode maps the given uncompressed SEC-encoded point to a random 64-byte bitstring.
func Encode(p []byte, rand io.Reader) ([]byte, error) {
	zero := new(fieldElement)

	if len(p) != 65 || p[0] != 4 {
		return nil, ErrInvalidPoint
	}

	var buf [64]byte
	for range 1_000 {
		// Generate a random field element \not\in {-1, 0, 1}.
		if _, err := io.ReadFull(rand, buf[:32]); err != nil {
			return nil, err
		}
		u := new(fieldElement).SetBytes(buf[:32])
		if u.CmpAbs(new(fieldElement).SetInt64(1)) == 0 || u.CmpAbs(zero) == 0 {
			continue
		}

		// Map the field element to a point and calculate the difference between the random point
		// and the input point: q = p - f(u).
		x1, y1 := new(fieldElement).SetBytes(p[1:33]), new(fieldElement).SetBytes(p[33:])
		x2, y2 := f(u)
		y2.Neg(y2)
		x3, y3 := p256Add(x1, y1, x2, y2)

		// If we managed to randomly generate -p, congratulate ourselves on the improbable and keep
		// trying.
		if x3.Cmp(zero) == 0 && y3.Cmp(zero) == 0 {
			continue
		}

		// Pick a random biquadratic root from [0,4).
		if _, err := io.ReadFull(rand, buf[:1]); err != nil {
			return nil, err
		}
		j := buf[0] % 4

		// If the Jth biquadratic root exists for the delta point, return our random field element
		// and our preimage field element: f(v) = q.
		v := r(x3, y3, j)
		if v != nil {
			copy(buf[:32], u.Bytes())
			copy(buf[32:], v.Bytes())
			return buf[:], nil
		}
	}

	panic("elliqator: failed to find candidate, suspect RNG failure")
}

func f(u *fieldElement) (x, y *fieldElement) {
	// Case 1: u \in {-1, 0, 1}
	// return: infinity
	zero := new(fieldElement)
	if u.CmpAbs(new(fieldElement).SetInt64(1)) == 0 || u.Cmp(zero) == 0 {
		return zero, zero
	}

	// Case 2: u \not\in {-1, 0, 1} and g(X_0(u)) is a square
	// return: (X_0(u), \sqrt{g(X_0(u))})
	x = x0(u)
	y = new(fieldElement).Sqrt(g(x))
	if y != nil {
		return x, y
	}

	// Case 3: u \not\in {-1, 0, 1} and g(X_0(u)) is not a square
	// return: (X_1(u), -\sqrt{g(X_1(u))})
	x = x1(u)
	y = new(fieldElement).Sqrt(g(x))
	if y == nil {
		panic("feSqrt(g(x)) returned nil")
	}
	y.Neg(y)
	return x, y
}

func r(x, y *fieldElement, j byte) *fieldElement {
	// Inverting `f` requires two branches, one for X_0 and one for X_1, each of which has four
	// roots. omega is constant across all of them.
	omega := new(fieldElement).SetB()
	omega.Invert(omega)
	omega.Mul(omega, new(fieldElement).SetA())
	omega.Mul(omega, x)
	omega.Add(omega, new(fieldElement).SetInt64(1))

	omega2 := new(fieldElement).Exp(omega, 2)
	fourOmega := new(fieldElement).Mul(omega, new(fieldElement).SetInt64(4))
	omega2Sub4Omega := new(fieldElement).Sub(omega2, fourOmega)

	a := new(fieldElement).Sqrt(omega2Sub4Omega)
	if a == nil {
		return nil
	}

	// The first division in roots comes at \sqrt{\omega^2 - 4 \omega}. The first and second
	// roots have positive values, the third and fourth roots have negative values.
	if j == 2 || j == 3 {
		a.Neg(a)
	}

	// If g(x) is square, then, x=X_0(u); otherwise x=X_1(u).
	var b = new(fieldElement)
	if new(fieldElement).Sqrt(y) != nil {
		// If x=X_0(u), then we divide by 2 \omega.
		b.Mul(new(fieldElement).SetInt64(2), omega)
		b.Invert(b)
	} else {
		// If x=X_1(u), then we divide by 2.
		b.Invert(new(fieldElement).SetInt64(2))
	}

	c := new(fieldElement).Add(omega, a)
	c.Mul(c, b)
	if c.Sqrt(c) == nil {
		return nil
	}

	// The second division in roots comes here. The first and third roots have positive
	// values, the second and fourth roots have negative values.
	if j == 1 || j == 3 {
		c.Neg(c)
	}

	return c
}

func g(x *fieldElement) *fieldElement {
	// x^3
	y := new(fieldElement).Exp(x, 3)

	// -3x
	y.Sub(y, x)
	y.Sub(y, x)
	y.Sub(y, x)

	// B
	y.Add(y, new(fieldElement).SetB())

	return y
}

func x0(u *fieldElement) *fieldElement {
	u2 := new(fieldElement).Exp(u, 2)
	b := new(fieldElement).Exp(u2, 2)
	b.Sub(b, u2)
	b.Invert(b)
	b.Add(b, new(fieldElement).SetInt64(1))

	a := new(fieldElement).SetA()
	a.Invert(a)
	a.Mul(a, new(fieldElement).SetB())
	a.Neg(a)
	b.Mul(a, b)

	return b
}

func x1(u *fieldElement) *fieldElement {
	y := new(fieldElement).Exp(u, 2)
	y.Neg(y)
	y.Mul(y, x0(u))
	return y
}
