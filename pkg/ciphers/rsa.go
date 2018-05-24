package ciphers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/jgblight/matasano/pkg/utils"
)

func egcd(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	zero := utils.GetBigInt(0)
	one := utils.GetBigInt(1)
	if a.Cmp(zero) == 0 {
		return b, zero, one
	}

	g, y, x := egcd(new(big.Int).Mod(b, a), a)
	i := new(big.Int).Div(b, a)
	i.Mul(i, y)
	i.Sub(x, i)
	return g, i, y
}

func InvMod(a, b *big.Int) (*big.Int, error) {
	g, x, _ := egcd(a, b)
	if g.Cmp(utils.GetBigInt(1)) == 0 {
		return new(big.Int).Mod(x, b), nil
	}
	return nil, errors.New("modular inverse does not exist")
}

func RSAKeygen() (*big.Int, *big.Int, *big.Int, error) {
	one := utils.GetBigInt(1)
	zero := utils.GetBigInt(0)

	e := utils.GetBigInt(3)
	p_e := utils.GetBigInt(0)
	var p *big.Int
	var err error
	for p_e.Cmp(zero) == 0 {
		p, err = rand.Prime(rand.Reader, 256)
		if err != nil {
			return nil, nil, nil, err
		}
		p_e.Mod(new(big.Int).Sub(p, one), e)
	}

	var q *big.Int
	q_e := utils.GetBigInt(0)
	for q_e.Cmp(zero) == 0 {
		q, err = rand.Prime(rand.Reader, 256)
		if err != nil {
			return nil, nil, nil, err
		}
		q_e.Mod(new(big.Int).Sub(q, one), e)
	}

	n := new(big.Int).Mul(p, q)
	tot := new(big.Int).Mul(p.Sub(p, one), q.Sub(q, one))
	d, err := InvMod(e, tot)
	if err != nil {
		return nil, nil, nil, err
	}
	return e, d, n, nil
}

func RSAEncrypt(plaintext []byte, e, n *big.Int) string {
	m := new(big.Int).SetBytes(plaintext)
	c := new(big.Int).Exp(m, e, n)
	return hex.EncodeToString(c.Bytes())
}

func RSADecrypt(ciphertext string, d, n *big.Int) ([]byte, error) {
	c, err := utils.HexToBigint(ciphertext)
	if err != nil {
		return nil, err
	}
	m := new(big.Int).Exp(c, d, n)
	return m.Bytes(), nil
}
