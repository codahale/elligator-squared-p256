package elligator_squared_p256

import (
	"crypto/subtle"
	"encoding/hex"
	"slices"

	"filippo.io/nistec"
	"github.com/mit-plv/fiat-crypto/fiat-go/64/p256"
)

func p256Affine(x, y *p256.MontgomeryDomainFieldElement) (*nistec.P256Point, error) {
	var encoded [65]byte
	encoded[0] = 4
	copy(encoded[1:33], feToBytes(x))
	copy(encoded[33:], feToBytes(y))
	return nistec.NewP256Point().SetBytes(encoded[:])
}

func feFromBytes(b []byte) *p256.MontgomeryDomainFieldElement {
	var (
		fe      p256.MontgomeryDomainFieldElement
		nonMont p256.NonMontgomeryDomainFieldElement
		bytes   [32]byte
	)

	if len(b) != 32 {
		panic("invalid field element length")
	}
	copy(bytes[:], b)
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
