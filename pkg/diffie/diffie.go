package diffie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"

	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/utils"
)

func CreateDHPublicKey(p, g *big.Int) (*big.Int, *big.Int, error) {
	// 256 bits
	maxInt, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
	a, err := rand.Int(rand.Reader, maxInt)
	if err != nil {
		return nil, nil, err
	}
	A := new(big.Int).Exp(g, a, p)
	return A, a, nil
}

func CreateDHSharedKey(A, b, p *big.Int) string {
	s := new(big.Int).Exp(A, b, p)
	return hashes.SHA1(s.Bytes())
}

type SRPClient struct {
	Email    string
	password string
	N        *big.Int
	g        *big.Int
	k        *big.Int
	salt     *big.Int
	_K       []byte
}

func NewSRPClient(email, password string) *SRPClient {
	return &SRPClient{
		Email:    email,
		password: password,
		N:        utils.GetNISTPrime(),
		g:        utils.GetBigInt(2),
		k:        utils.GetBigInt(3),
	}
}

type keyResponse struct {
	Salt string `json:"salt"`
	B    string `json:"B"`
	U    string `json:"u"`
}

func SRPKeyRequest(email string, A *big.Int) (*big.Int, *big.Int, error) {
	resp, err := http.PostForm("http://localhost:1323/establishKey", url.Values{
		"email": {string(email)},
		"A":     {A.Text(16)},
	})
	if err != nil {
		return nil, nil, err
	}

	decoder := json.NewDecoder(resp.Body)
	var r keyResponse
	err = decoder.Decode(&r)
	if err != nil {
		return nil, nil, err
	}

	salt, saltOk := new(big.Int).SetString(r.Salt, 16)
	if !saltOk {
		return nil, nil, errors.New("Could not parse salt from server")
	}
	B, BOk := new(big.Int).SetString(r.B, 16)
	if !BOk {
		return nil, nil, errors.New("Could not parse B from server")
	}
	return salt, B, nil
}

func SimpleSRPKeyRequest(email string, A *big.Int) (*big.Int, *big.Int, *big.Int, error) {
	resp, err := http.PostForm("http://localhost:1323/simpleEstablishKey", url.Values{
		"email": {string(email)},
		"A":     {A.Text(16)},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	decoder := json.NewDecoder(resp.Body)
	var r keyResponse
	err = decoder.Decode(&r)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, saltOk := new(big.Int).SetString(r.Salt, 16)
	if !saltOk {
		return nil, nil, nil, errors.New("Could not parse salt from server")
	}
	B, BOk := new(big.Int).SetString(r.B, 16)
	if !BOk {
		return nil, nil, nil, errors.New("Could not parse B from server")
	}
	u, uOk := new(big.Int).SetString(r.U, 16)
	if !uOk {
		return nil, nil, nil, errors.New("Could not parse u from server")
	}
	return salt, B, u, nil
}

func SRPVerifyKeyRequest(mac []byte) (bool, error) {
	resp, err := http.PostForm("http://localhost:1323/verifyKey", url.Values{
		"mac": {string(mac)},
	})
	if err != nil {
		return false, err
	}
	return resp.StatusCode == 200, nil
}

func (srp *SRPClient) Initialize() error {
	_, err := http.PostForm("http://localhost:1323/setSRPParams", url.Values{
		"email":    {srp.Email},
		"password": {srp.password},
		"N":        {srp.N.Text(16)},
		"g":        {srp.g.String()},
		"k":        {srp.k.String()},
	})
	if err != nil {
		return err
	}
	return nil
}

func (srp *SRPClient) EstablishKey() error {
	A, a, err := CreateDHPublicKey(srp.N, srp.g)
	if err != nil {
		return err
	}

	salt, B, err := SRPKeyRequest(srp.Email, A)
	if err != nil {
		return err
	}

	srp.salt = salt
	xH := sha256.Sum256(append(salt.Bytes(), []byte(srp.password)...))
	x := new(big.Int).SetBytes(xH[:])

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	Bmin := new(big.Int).Mul(srp.k, new(big.Int).Exp(srp.g, x, srp.N))
	base := new(big.Int).Sub(B, Bmin)
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, srp.N)
	K := sha256.Sum256(S.Bytes())
	srp._K = K[:]

	return nil
}

type SimpleKeyRequestFunc func(string, *big.Int) (*big.Int, *big.Int, *big.Int, error)

func (srp *SRPClient) SimpleEstablishKey() error {
	return srp.simpleEstablishKey(SimpleSRPKeyRequest)
}

func (srp *SRPClient) MITMSimpleEstablishKey(request SimpleKeyRequestFunc) error {
	return srp.simpleEstablishKey(request)
}

func (srp *SRPClient) simpleEstablishKey(request SimpleKeyRequestFunc) error {
	A, a, err := CreateDHPublicKey(srp.N, srp.g)
	if err != nil {
		return err
	}

	salt, B, u, err := request(srp.Email, A)
	if err != nil {
		return err
	}

	srp.salt = salt
	xH := sha256.Sum256(append(salt.Bytes(), []byte(srp.password)...))
	x := new(big.Int).SetBytes(xH[:])

	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(B, exp, srp.N)
	K := sha256.Sum256(S.Bytes())
	srp._K = K[:]

	return nil
}

type VerifyKeyRequestFunc func([]byte) (bool, error)

func (srp *SRPClient) VerifyKey() (bool, error) {
	return srp.verifyKey(SRPVerifyKeyRequest)
}

func (srp *SRPClient) MITMVerifyKey(request VerifyKeyRequestFunc) (bool, error) {
	return srp.verifyKey(request)
}

func (srp *SRPClient) verifyKey(request VerifyKeyRequestFunc) (bool, error) {
	mac := hmac.New(sha256.New, srp._K)
	mac.Write(srp.salt.Bytes())
	return request(mac.Sum(nil))
}

func (srp *SRPClient) CheckPassword(password string) bool {
	return password == srp.password
}
