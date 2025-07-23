package elligator

import (
	"errors"
	"io"

	"github.com/mit-plv/fiat-crypto/fiat-go/64/p256"
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

	u, v := feFromBytes(b[:32]), feFromBytes(b[32:])
	x1, y1 := f(u)
	x2, y2 := f(v)
	x3, y3 := p256Add(x1, y1, x2, y2)

	var out [65]byte
	out[0] = 4
	copy(out[1:33], feToBytes(x3))
	copy(out[33:], feToBytes(y3))
	return out[:], nil
}

// Encode maps the given uncompressed SEC-encoded point to a random 64-byte bitstring.
//
// Panics if reading from rand returns an error.
func Encode(p []byte, rand io.Reader) ([]byte, error) {
	if len(p) != 65 || p[0] != 4 {
		return nil, ErrInvalidPoint
	}

	var buf [64]byte
	for i := 0; i < 1_000_000; i++ {
		// Generate a random field element \not\in {-1, 0, 1}.
		if _, err := io.ReadFull(rand, buf[:32]); err != nil {
			panic(err)
		}
		u := feFromBytes(buf[:32])
		if feEqual(u, &negOne) || feEqual(u, &zero) || feEqual(u, &one) {
			continue
		}

		// Map the field element to a point and calculate the difference between the random point
		// and the input point.
		x1, y1 := feFromBytes(p[1:33]), feFromBytes(p[33:])
		x2, y2 := f(u)
		p256.Opp(y2, y2)
		x3, y3 := p256Add(x1, y1, x2, y2)

		// If we managed to randomly generate -p, congratulate ourselves on the improbable and keep
		// trying.
		if feEqual(x3, &zero) && feEqual(y3, &zero) {
			continue
		}

		// Pick a random biquadratic root from [0,4).
		if _, err := io.ReadFull(rand, buf[:1]); err != nil {
			panic(err)
		}
		j := buf[0] % 4

		// If the Jth biquadratic root exists for the delta point, return our random field element
		// and our preimage field element.
		v := r(x3, y3, j)
		if v != nil {
			copy(buf[:32], feToBytes(u))
			copy(buf[32:], feToBytes(v))
			return buf[:], nil
		}
	}

	panic("elliqator: failed to find candidate, suspect RNG failure")
}

func f(u *p256.MontgomeryDomainFieldElement) (x, y *p256.MontgomeryDomainFieldElement) {
	// Case 1: u \in {-1, 0, 1}
	// return: infinity
	if feEqual(u, &one) || feEqual(u, &zero) || feEqual(u, &negOne) {
		return &zero, &zero
	}

	// Case 2: u \not\in {-1, 0, 1} and g(X_0(u)) is a square
	// return: (X_0(u), \sqrt{g(X_0(u))})
	x = x0(u)
	y = feSqrt(g(x))
	if y != nil {
		return x, y
	}

	// Case 3: u \not\in {-1, 0, 1} and g(X_0(u)) is not a square
	// return: (X_1(u), -\sqrt{g(X_1(u))})
	x = x1(u)
	y = feSqrt(g(x))
	if y == nil {
		panic("feSqrt(g(x)) returned nil")
	}
	p256.Opp(y, y)
	return x, y
}

func r(x, y *p256.MontgomeryDomainFieldElement, j byte) *p256.MontgomeryDomainFieldElement {
	// Inverting `f` requires two branches, one for X_0 and one for X_1, each of which has four
	// roots. omega is constant across all of them.
	omega := feInvert(&curveB)
	p256.Mul(omega, &curveA, omega)
	p256.Mul(omega, omega, x)
	p256.Add(omega, omega, &one)

	var omega2Sub4Omega, omega2, fourOmega p256.MontgomeryDomainFieldElement
	p256.Square(&omega2, omega)
	p256.Mul(&fourOmega, omega, &four)
	p256.Sub(&omega2Sub4Omega, &omega2, &fourOmega)

	a := feSqrt(&omega2Sub4Omega)
	if a == nil {
		return nil
	}

	// The first division in roots comes at \sqrt{\omega^2 - 4 \omega}. The first and second
	// roots have positive values, the third and fourth roots have negative values.
	if j == 2 || j == 3 {
		p256.Opp(a, a)
	}

	// If g(x) is square, then, x=X_0(u); otherwise x=X_1(u).
	var b = new(p256.MontgomeryDomainFieldElement)
	if feSqrt(y) != nil {
		// If x=X_0(u), then we divide by 2 \omega.
		p256.Mul(b, &two, omega)
		b = feInvert(b)
	} else {
		// If x=X_1(u), then we divide by 2.
		b = feInvert(&two)
	}

	c := new(p256.MontgomeryDomainFieldElement)
	p256.Add(c, omega, a)
	p256.Mul(c, c, b)
	c = feSqrt(c)
	if c == nil {
		return nil
	}

	// The second division in roots comes here. The first and third roots have positive
	// values, the second and fourth roots have negative values.
	if j == 1 || j == 3 {
		p256.Opp(c, c)
	}

	return c
}

func g(x *p256.MontgomeryDomainFieldElement) *p256.MontgomeryDomainFieldElement {
	// x^3
	var y p256.MontgomeryDomainFieldElement
	p256.Square(&y, x)
	p256.Mul(&y, &y, x)

	// -3x
	p256.Sub(&y, &y, x)
	p256.Sub(&y, &y, x)
	p256.Sub(&y, &y, x)

	// B
	p256.Add(&y, &y, &curveB)

	return &y
}

func x0(u *p256.MontgomeryDomainFieldElement) *p256.MontgomeryDomainFieldElement {
	negBdivA := feInvert(&curveA)
	p256.Mul(negBdivA, &curveB, negBdivA)
	p256.Opp(negBdivA, negBdivA)

	var (
		u2, u4, u4SubU2, y p256.MontgomeryDomainFieldElement
	)
	p256.Square(&u2, u)
	p256.Square(&u4, &u2)
	p256.Sub(&u4SubU2, &u4, &u2)
	i := feInvert(&u4SubU2)
	p256.Add(i, i, &one)

	p256.Mul(&y, negBdivA, i)
	return &y
}

func x1(u *p256.MontgomeryDomainFieldElement) *p256.MontgomeryDomainFieldElement {
	var y p256.MontgomeryDomainFieldElement
	p256.Square(&y, u)
	p256.Opp(&y, &y)
	p256.Mul(&y, &y, x0(u))
	return &y
}
