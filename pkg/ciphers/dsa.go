package ciphers

import (
	"crypto/rand"
	"math/big"

	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/utils"
)

type DSAParams struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

func NewDSAParams() (*DSAParams, error) {
	p, _ := new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	q, _ := new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	g, _ := new(big.Int).SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

	return &DSAParams{P: p, Q: q, G: g}, nil
}

func DSAKeygen(params *DSAParams) (*big.Int, *big.Int, error) {
	x, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, nil, err
	}
	y := new(big.Int).Exp(params.G, x, params.P)
	return x, y, nil
}

type DSASignature struct {
	R *big.Int
	S *big.Int
}

func DSASign(m []byte, x *big.Int, params *DSAParams) (*DSASignature, error) {
	k := new(big.Int)
	r := utils.GetBigInt(0)
	s := utils.GetBigInt(0)

	hash, err := utils.HexToBigint(hashes.SHA1(m))
	if err != nil {
		return nil, err
	}

	k, err = rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, err
	}

	r = r.Mod(r.Exp(params.G, k, params.P), params.Q)

	k1 := new(big.Int).ModInverse(k, params.Q)
	s = s.Mod(s.Mul(k1, s.Add(hash, s.Mul(x, r))), params.Q)
	return &DSASignature{r, s}, nil
}

func DSAVerify(m []byte, sig *DSASignature, y *big.Int, params *DSAParams) (bool, error) {
	if sig.R.Cmp(params.Q) >= 0 || sig.R.Cmp(params.Q) >= 0 {
		return false, nil
	}

	hash, err := utils.HexToBigint(hashes.SHA1(m))
	if err != nil {
		return false, err
	}

	w := new(big.Int).ModInverse(sig.S, params.Q)
	u1 := new(big.Int).Mod(new(big.Int).Mul(hash, w), params.Q)
	u2 := new(big.Int).Mod(new(big.Int).Mul(sig.R, w), params.Q)

	v1 := new(big.Int).Exp(params.G, u1, params.P)
	v2 := new(big.Int).Exp(y, u2, params.P)
	v := new(big.Int)
	v = v.Mod(v.Mod(v.Mul(v1, v2), params.P), params.Q)

	return v.Cmp(sig.R) == 0, nil
}
