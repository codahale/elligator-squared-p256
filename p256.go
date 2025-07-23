package elligator_squared_p256

import (
	"crypto/subtle"
	"encoding/hex"
	"slices"

	"github.com/mit-plv/fiat-crypto/fiat-go/64/p256"
)

func p256Add(x1, y1, x2, y2 *p256.MontgomeryDomainFieldElement) (x3, y3 *p256.MontgomeryDomainFieldElement) {
	// Complete addition formula for a = -3 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	var z1, z2, t0, t1, t2, t3, t4 p256.MontgomeryDomainFieldElement
	x3 = new(p256.MontgomeryDomainFieldElement)
	y3 = new(p256.MontgomeryDomainFieldElement)
	z3 := new(p256.MontgomeryDomainFieldElement)

	// Convert to projective.
	if !feEqual(x1, &zero) || !feEqual(y1, &zero) {
		p256.SetOne(&z1)
	}
	if !feEqual(x2, &zero) || !feEqual(y2, &zero) {
		p256.SetOne(&z2)
	}

	p256.Mul(&t0, x1, x2)      // t0 := X1 * X2
	p256.Mul(&t1, y1, y2)      // t1 := Y1 * Y2
	p256.Mul(&t2, &z1, &z2)    // t2 := Z1 * Z2
	p256.Add(&t3, x1, y1)      // t3 := X1 + Y1
	p256.Add(&t4, x2, y2)      // t4 := X2 + Y2
	p256.Mul(&t3, &t3, &t4)    // t3 := t3 * t4
	p256.Add(&t4, &t0, &t1)    // t4 := t0 + t1
	p256.Sub(&t3, &t3, &t4)    // t3 := t3 - t4
	p256.Add(&t4, y1, &z1)     // t4 := Y1 + Z1
	p256.Add(x3, y2, &z2)      // X3 := Y2 + Z2
	p256.Mul(&t4, &t4, x3)     // t4 := t4 * X3
	p256.Add(x3, &t1, &t2)     // X3 := t1 + t2
	p256.Sub(&t4, &t4, x3)     // t4 := t4 - X3
	p256.Add(x3, x1, &z1)      // X3 := X1 + Z1
	p256.Add(y3, x2, &z2)      // Y3 := X2 + Z2
	p256.Mul(x3, x3, y3)       // X3 := X3 * Y3
	p256.Add(y3, &t0, &t2)     // Y3 := t0 + t2
	p256.Sub(y3, x3, y3)       // Y3 := X3 - Y3
	p256.Mul(z3, &curveB, &t2) // Z3 := b * t2
	p256.Sub(x3, y3, z3)       // X3 := Y3 - Z3
	p256.Add(z3, x3, x3)       // Z3 := X3 + X3
	p256.Add(x3, x3, z3)       // X3 := X3 + Z3
	p256.Sub(z3, &t1, x3)      // Z3 := t1 - X3
	p256.Add(x3, &t1, x3)      // X3 := t1 + X3
	p256.Mul(y3, &curveB, y3)  // Y3 := b * Y3
	p256.Add(&t1, &t2, &t2)    // t1 := t2 + t2
	p256.Add(&t2, &t1, &t2)    // t2 := t1 + t2
	p256.Sub(y3, y3, &t2)      // Y3 := Y3 - t2
	p256.Sub(y3, y3, &t0)      // Y3 := Y3 - t0
	p256.Add(&t1, y3, y3)      // t1 := Y3 + Y3
	p256.Add(y3, &t1, y3)      // Y3 := t1 + Y3
	p256.Add(&t1, &t0, &t0)    // t1 := t0 + t0
	p256.Add(&t0, &t1, &t0)    // t0 := t1 + t0
	p256.Sub(&t0, &t0, &t2)    // t0 := t0 - t2
	p256.Mul(&t1, &t4, y3)     // t1 := t4 * Y3
	p256.Mul(&t2, &t0, y3)     // t2 := t0 * Y3
	p256.Mul(y3, x3, z3)       // Y3 := X3 * Z3
	p256.Add(y3, y3, &t2)      // Y3 := Y3 + t2
	p256.Mul(x3, &t3, x3)      // X3 := t3 * X3
	p256.Sub(x3, x3, &t1)      // X3 := X3 - t1
	p256.Mul(z3, &t4, z3)      // Z3 := t4 * Z3
	p256.Mul(&t1, &t3, &t0)    // t1 := t3 * t0
	p256.Add(z3, z3, &t1)      // Z3 := Z3 + t1

	z3Inv := feInvert(z3)
	p256.Mul(x3, x3, z3Inv)
	p256.Mul(y3, y3, z3Inv)

	return x3, y3
}

func feFromBytes(b []byte) *p256.MontgomeryDomainFieldElement {
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
	return &fe
}

func feToBytes(fe *p256.MontgomeryDomainFieldElement) []byte {
	var (
		nonMont p256.NonMontgomeryDomainFieldElement
		bytes   [32]byte
	)
	p256.FromMontgomery(&nonMont, fe)
	p256.ToBytes(&bytes, (*[4]uint64)(&nonMont))
	slices.Reverse(bytes[:])
	return bytes[:]
}

func feFromHex(s string) *p256.MontgomeryDomainFieldElement {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return feFromBytes(b)
}

func feEqual(a, b *p256.MontgomeryDomainFieldElement) bool {
	return subtle.ConstantTimeCompare(feToBytes(a), feToBytes(b)) == 1
}

func feInvert(x *p256.MontgomeryDomainFieldElement) *p256.MontgomeryDomainFieldElement {
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
		z, t0, t1 p256.MontgomeryDomainFieldElement
	)

	p256.Square(&z, x)
	p256.Mul(&z, x, &z)
	p256.Square(&z, &z)
	p256.Mul(&z, x, &z)
	p256.Square(&t0, &z)
	for s := 1; s < 3; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(&t0, &z, &t0)
	p256.Square(&t1, &t0)
	for s := 1; s < 6; s++ {
		p256.Square(&t1, &t1)
	}
	p256.Mul(&t0, &t0, &t1)
	for s := 0; s < 3; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(&z, &z, &t0)
	p256.Square(&t0, &z)
	p256.Mul(&t0, x, &t0)
	p256.Square(&t1, &t0)
	for s := 1; s < 16; s++ {
		p256.Square(&t1, &t1)
	}
	p256.Mul(&t0, &t0, &t1)
	for s := 0; s < 15; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(&z, &z, &t0)
	for s := 0; s < 17; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(&t0, x, &t0)
	for s := 0; s < 143; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(&t0, &z, &t0)
	for s := 0; s < 47; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(&z, &z, &t0)
	for s := 0; s < 2; s++ {
		p256.Square(&z, &z)
	}
	p256.Mul(&z, x, &z)

	return &z
}

func feSqrt(x *p256.MontgomeryDomainFieldElement) *p256.MontgomeryDomainFieldElement {
	var candidate, square p256.MontgomeryDomainFieldElement
	feSqrtCandidate(&candidate, x)
	p256.Square(&square, &candidate)
	if !feEqual(&square, x) {
		return nil
	}
	return &candidate
}

func feSqrtCandidate(z, x *p256.MontgomeryDomainFieldElement) {
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
	var t0 p256.MontgomeryDomainFieldElement

	p256.Square(z, x)
	p256.Mul(z, x, z)
	p256.Square(&t0, z)
	for s := 1; s < 2; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(z, z, &t0)
	p256.Square(&t0, z)
	for s := 1; s < 4; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(z, z, &t0)
	p256.Square(&t0, z)
	for s := 1; s < 8; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(z, z, &t0)
	p256.Square(&t0, z)
	for s := 1; s < 16; s++ {
		p256.Square(&t0, &t0)
	}
	p256.Mul(z, z, &t0)
	for s := 0; s < 32; s++ {
		p256.Square(z, z)
	}
	p256.Mul(z, x, z)
	for s := 0; s < 96; s++ {
		p256.Square(z, z)
	}
	p256.Mul(z, x, z)
	for s := 0; s < 94; s++ {
		p256.Square(z, z)
	}
}

var (
	zero, one, two, four, negOne, curveA, curveB p256.MontgomeryDomainFieldElement
)

func init() {
	p256.SetOne(&one)
	p256.Add(&two, &one, &one)
	p256.Add(&four, &two, &two)
	p256.Sub(&curveA, &one, &four)
	p256.Opp(&negOne, &one)
	curveB = *feFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
}
