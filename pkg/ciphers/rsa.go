package ciphers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/jgblight/matasano/pkg/hashes"
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

func RSAKeygen(i int) (*big.Int, *big.Int, *big.Int, error) {
	one := utils.GetBigInt(1)
	zero := utils.GetBigInt(0)

	e := utils.GetBigInt(3)
	p_e := utils.GetBigInt(0)
	var p *big.Int
	var err error
	for p_e.Cmp(zero) == 0 {
		p, err = rand.Prime(rand.Reader, i/2)
		if err != nil {
			return nil, nil, nil, err
		}
		p_e.Mod(new(big.Int).Sub(p, one), e)
	}

	var q *big.Int
	q_e := utils.GetBigInt(0)
	for q_e.Cmp(zero) == 0 {
		q, err = rand.Prime(rand.Reader, i/2)
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

func PKCS15Sign(plaintext []byte, d, n *big.Int) (string, error) {
	k := n.BitLen() / 8
	hash, err := hex.DecodeString(hashes.SHA1(plaintext))
	if err != nil {
		return "", err
	}

	padding := utils.MakeRepeatChar('\xff', k-3-len(hash))
	padded := append([]byte("\x00\x01"), padding...)
	padded = append(padded, '\x00')
	padded = append(padded, hash...)

	return RSAEncrypt(padded, d, n), nil
}

func PKCS15Verify(plaintext []byte, ciphertext string, e, n *big.Int) bool {
	padded, err := RSADecrypt(ciphertext, e, n)
	if err != nil {
		return false
	}
	k := n.BitLen() / 8
	if len(padded) == k-1 {
		padded = append([]byte("\x00"), padded...)
	}

	if len(padded) != k {
		return false
	}

	if padded[0] != '\x00' || padded[1] != '\x01' {
		return false
	}
	i := 2
	c := padded[i]
	for c == '\xff' {
		i += 1
		c = padded[i]
	}
	if padded[i] != '\x00' {
		return false
	}
	hash := hex.EncodeToString(padded[i+1 : i+21])
	expectedHash := hashes.SHA1(plaintext)

	if hash == expectedHash {
		return true
	}
	return false
}

func PKCS15Encrypt(plaintext []byte, d, n *big.Int) string {
	k := n.BitLen() / 8

	padding := utils.MakeRepeatChar('\xff', k-3-len(plaintext))
	padded := append([]byte("\x00\x02"), padding...)
	padded = append(padded, '\x00')
	padded = append(padded, plaintext...)

	return RSAEncrypt(padded, d, n)
}
