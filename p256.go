package elligator

import (
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"slices"

	"github.com/mit-plv/fiat-crypto/fiat-go/64/p256"
)

type fieldElement struct {
	v p256.MontgomeryDomainFieldElement
}

func (e *fieldElement) SetOne() *fieldElement {
	p256.SetOne(&e.v)
	return e
}

func (e *fieldElement) Add(x, y *fieldElement) *fieldElement {
	p256.Add(&e.v, &x.v, &y.v)
	return e
}

func (e *fieldElement) Sub(x, y *fieldElement) *fieldElement {
	p256.Sub(&e.v, &x.v, &y.v)
	return e
}

func (e *fieldElement) Mul(x, y *fieldElement) *fieldElement {
	p256.Mul(&e.v, &x.v, &y.v)
	return e
}

func (e *fieldElement) Square(x *fieldElement) *fieldElement {
	p256.Square(&e.v, &x.v)
	return e
}

func (e *fieldElement) Neg(x *fieldElement) *fieldElement {
	p256.Opp(&e.v, &x.v)
	return e
}

func (e *fieldElement) Invert(x *fieldElement) *fieldElement {
	// Inversion is implemented as exponentiation with exponent p − 2.
	// The sequence of 12 multiplications and 255 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10     = 2*1
	//	_11     = 1 + _10
	//	_110    = 2*_11
	//	_111    = 1 + _110
	//	_111000 = _111 << 3
	//	_111111 = _111 + _111000
	//	x12     = _111111 << 6 + _111111
	//	x15     = x12 << 3 + _111
	//	x16     = 2*x15 + 1
	//	x32     = x16 << 16 + x16
	//	i53     = x32 << 15
	//	x47     = x15 + i53
	//	i263    = ((i53 << 17 + 1) << 143 + x47) << 47
	//	return    (x47 + i263) << 2 + 1
	//
	var (
		y, t0, t1 fieldElement
	)

	y.Square(x)
	y.Mul(x, &y)
	y.Square(&y)
	y.Mul(x, &y)
	t0.Square(&y)
	for s := 1; s < 3; s++ {
		t0.Square(&t0)
	}
	t0.Mul(&y, &t0)
	t1.Square(&t0)
	for s := 1; s < 6; s++ {
		t1.Square(&t1)
	}
	t0.Mul(&t0, &t1)
	for s := 0; s < 3; s++ {
		t0.Square(&t0)
	}
	y.Mul(&y, &t0)
	t0.Square(&y)
	t0.Mul(x, &t0)
	t1.Square(&t0)
	for s := 1; s < 16; s++ {
		t1.Square(&t1)
	}
	t0.Mul(&t0, &t1)
	for s := 0; s < 15; s++ {
		t0.Square(&t0)
	}
	y.Mul(&y, &t0)
	for s := 0; s < 17; s++ {
		t0.Square(&t0)
	}
	t0.Mul(x, &t0)
	for s := 0; s < 143; s++ {
		t0.Square(&t0)
	}
	t0.Mul(&y, &t0)
	for s := 0; s < 47; s++ {
		t0.Square(&t0)
	}
	y.Mul(&y, &t0)
	for s := 0; s < 2; s++ {
		y.Square(&y)
	}
	y.Mul(x, &y)

	*e = y
	return e
}

func (e *fieldElement) Bytes() []byte {
	var (
		nonMont p256.NonMontgomeryDomainFieldElement
		bytes   [32]byte
	)
	p256.FromMontgomery(&nonMont, &e.v)
	p256.ToBytes(&bytes, (*[4]uint64)(&nonMont))
	slices.Reverse(bytes[:])
	return bytes[:]
}

func (e *fieldElement) String() string {
	return hex.EncodeToString(e.Bytes())
}

func (e *fieldElement) Equal(x *fieldElement) bool {
	return subtle.ConstantTimeCompare(e.Bytes(), x.Bytes()) == 1
}

func (e *fieldElement) Sqrt(x *fieldElement) *fieldElement {
	feSqrtCandidate := func(z, x *fieldElement) {
		// Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
		//
		// The sequence of 7 multiplications and 253 squarings is derived from the
		// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
		//
		//	_10       = 2*1
		//	_11       = 1 + _10
		//	_1100     = _11 << 2
		//	_1111     = _11 + _1100
		//	_11110000 = _1111 << 4
		//	_11111111 = _1111 + _11110000
		//	x16       = _11111111 << 8 + _11111111
		//	x32       = x16 << 16 + x16
		//	return      ((x32 << 32 + 1) << 96 + 1) << 94
		//
		var t0 fieldElement

		z.Square(x)
		z.Mul(x, z)
		t0.Square(z)
		for s := 1; s < 2; s++ {
			t0.Square(&t0)
		}
		z.Mul(z, &t0)
		t0.Square(z)
		for s := 1; s < 4; s++ {
			t0.Square(&t0)
		}
		z.Mul(z, &t0)
		t0.Square(z)
		for s := 1; s < 8; s++ {
			t0.Square(&t0)
		}
		z.Mul(z, &t0)
		t0.Square(z)
		for s := 1; s < 16; s++ {
			t0.Square(&t0)
		}
		z.Mul(z, &t0)
		for s := 0; s < 32; s++ {
			z.Square(z)
		}
		z.Mul(x, z)
		for s := 0; s < 96; s++ {
			z.Square(z)
		}
		z.Mul(x, z)
		for s := 0; s < 94; s++ {
			z.Square(z)
		}
	}

	var candidate, square fieldElement
	feSqrtCandidate(&candidate, x)
	square.Square(&candidate)
	if !square.Equal(x) {
		return nil
	}
	return &candidate
}

func p256Add(x1, y1, x2, y2 *fieldElement) (x3, y3 *fieldElement) {
	// Complete addition formula for a = -3 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	z1 := new(fieldElement)
	z2 := new(fieldElement)

	// Convert to projective.
	if !x1.Equal(&zero) || !y1.Equal(&zero) {
		z1.SetOne()
	}
	if !x2.Equal(&zero) || !y2.Equal(&zero) {
		z2.SetOne()
	}

	t0 := new(fieldElement).Mul(x1, x2)      // t0 := X1 * X2
	t1 := new(fieldElement).Mul(y1, y2)      // t1 := Y1 * Y2
	t2 := new(fieldElement).Mul(z1, z2)      // t2 := Z1 * Z2
	t3 := new(fieldElement).Add(x1, y1)      // t3 := X1 + Y1
	t4 := new(fieldElement).Add(x2, y2)      // t4 := X2 + Y2
	t3.Mul(t3, t4)                           // t3 := t3 * t4
	t4.Add(t0, t1)                           // t4 := t0 + t1
	t3.Sub(t3, t4)                           // t3 := t3 - t4
	t4.Add(y1, z1)                           // t4 := Y1 + Z1
	x3 = new(fieldElement).Add(y2, z2)       // X3 := Y2 + Z2
	t4.Mul(t4, x3)                           // t4 := t4 * X3
	x3.Add(t1, t2)                           // X3 := t1 + t2
	t4.Sub(t4, x3)                           // t4 := t4 - X3
	x3.Add(x1, z1)                           // X3 := X1 + Z1
	y3 = new(fieldElement).Add(x2, z2)       // Y3 := X2 + Z2
	x3.Mul(x3, y3)                           // X3 := X3 * Y3
	y3.Add(t0, t2)                           // Y3 := t0 + t2
	y3.Sub(x3, y3)                           // Y3 := X3 - Y3
	z3 := new(fieldElement).Mul(&curveB, t2) // Z3 := b * t2
	x3.Sub(y3, z3)                           // X3 := Y3 - Z3
	z3.Add(x3, x3)                           // Z3 := X3 + X3
	x3.Add(x3, z3)                           // X3 := X3 + Z3
	z3.Sub(t1, x3)                           // Z3 := t1 - X3
	x3.Add(t1, x3)                           // X3 := t1 + X3
	y3.Mul(&curveB, y3)                      // Y3 := b * Y3
	t1.Add(t2, t2)                           // t1 := t2 + t2
	t2.Add(t1, t2)                           // t2 := t1 + t2
	y3.Sub(y3, t2)                           // Y3 := Y3 - t2
	y3.Sub(y3, t0)                           // Y3 := Y3 - t0
	t1.Add(y3, y3)                           // t1 := Y3 + Y3
	y3.Add(t1, y3)                           // Y3 := t1 + Y3
	t1.Add(t0, t0)                           // t1 := t0 + t0
	t0.Add(t1, t0)                           // t0 := t1 + t0
	t0.Sub(t0, t2)                           // t0 := t0 - t2
	t1.Mul(t4, y3)                           // t1 := t4 * Y3
	t2.Mul(t0, y3)                           // t2 := t0 * Y3
	y3.Mul(x3, z3)                           // Y3 := X3 * Z3
	y3.Add(y3, t2)                           // Y3 := Y3 + t2
	x3.Mul(t3, x3)                           // X3 := t3 * X3
	x3.Sub(x3, t1)                           // X3 := X3 - t1
	z3.Mul(t4, z3)                           // Z3 := t4 * Z3
	t1.Mul(t3, t0)                           // t1 := t3 * t0
	z3.Add(z3, t1)                           // Z3 := Z3 + t1

	z3Inv := new(fieldElement).Invert(z3)
	x3.Mul(x3, z3Inv)
	y3.Mul(y3, z3Inv)

	return x3, y3
}

func feFromBytes(b []byte) *fieldElement {
	var (
		fe      p256.MontgomeryDomainFieldElement
		nonMont p256.NonMontgomeryDomainFieldElement
		bytes   [32]byte
	)

	if len(b) > 32 {
		panic("invalid field element length")
	}
	copy(bytes[32-len(b):], b) // pad with zeroes
	slices.Reverse(bytes[:])
	p256.FromBytes((*[4]uint64)(&nonMont), &bytes)
	p256.ToMontgomery(&fe, &nonMont)
	return &fieldElement{v: fe}
}

func feFromHex(s string) *fieldElement {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return feFromBytes(b)
}

var (
	zero, one, two, four, negOne, curveA, curveB fieldElement
)

func init() {
	one.SetOne()
	two.Add(&one, &one)
	four.Add(&two, &two)
	curveA.Sub(&one, &four)
	negOne.Neg(&one)
	curveB = *feFromBytes(elliptic.P256().Params().B.Bytes())
}
