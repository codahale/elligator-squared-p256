package elligator

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
)

type fieldElement struct {
	v big.Int
}

func (e *fieldElement) Add(x, y *fieldElement) *fieldElement {
	e.v.Add(&x.v, &y.v)
	e.v.Mod(&e.v, elliptic.P256().Params().P)
	return e
}

func (e *fieldElement) Sub(x, y *fieldElement) *fieldElement {
	e.v.Sub(&x.v, &y.v)
	e.v.Mod(&e.v, elliptic.P256().Params().P)
	return e
}

func (e *fieldElement) Mul(x, y *fieldElement) *fieldElement {
	e.v.Mul(&x.v, &y.v)
	e.v.Mod(&e.v, elliptic.P256().Params().P)
	return e
}

func (e *fieldElement) Square(x *fieldElement) *fieldElement {
	e.v.Exp(&x.v, &two.v, elliptic.P256().Params().P)
	return e
}

func (e *fieldElement) Neg(x *fieldElement) *fieldElement {
	e.v.Neg(&x.v)
	e.v.Mod(&e.v, elliptic.P256().Params().P)
	return e
}

func (e *fieldElement) Invert(x *fieldElement) *fieldElement {
	e.v.ModInverse(&x.v, elliptic.P256().Params().P)
	return e
}

func (e *fieldElement) Bytes() []byte {
	var bytes [32]byte
	e.v.FillBytes(bytes[:])
	return bytes[:]
}

func (e *fieldElement) String() string {
	return hex.EncodeToString(e.Bytes())
}

func (e *fieldElement) Equal(x *fieldElement) bool {
	return e.v.Cmp(&x.v) == 0
}

func (e *fieldElement) Sqrt(x *fieldElement) *fieldElement {
	var candidate, square fieldElement
	candidate.v.ModSqrt(&x.v, elliptic.P256().Params().P)
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
		z1.v.SetInt64(1)
	}
	if !x2.Equal(&zero) || !y2.Equal(&zero) {
		z2.v.SetInt64(1)
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
	var f fieldElement
	f.v.SetBytes(b)
	return &f
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
	one.v.SetInt64(1)
	two.v.SetInt64(2)
	four.v.SetInt64(4)
	negOne.v.SetInt64(-1)
	curveA.v.SetInt64(-3)
	curveB = *feFromBytes(elliptic.P256().Params().B.Bytes())
}
