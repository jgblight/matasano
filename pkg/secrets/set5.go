package secrets

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"

	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/diffie"
	"github.com/jgblight/matasano/pkg/utils"
)

type DHProtocolUser struct {
	Name     string
	p        *big.Int
	g        *big.Int
	myKey    *big.Int
	theirKey *big.Int
	shared   []byte
}

func NewDHUser(name string) *DHProtocolUser {
	dh := &DHProtocolUser{}
	dh.Name = name
	return dh
}

func (dh *DHProtocolUser) createParams() {
	dh.p = utils.GetNISTPrime()
	dh.g = utils.GetBigInt(2)
}

func (dh *DHProtocolUser) createSharedKey() {
	if dh.myKey != nil && dh.theirKey != nil {
		sharedKey, _ := hex.DecodeString(diffie.CreateDHSharedKey(dh.theirKey, dh.myKey, dh.p))
		dh.shared = sharedKey[:16]
	}
}

func (dh *DHProtocolUser) SendKeyAndParams() (*big.Int, *big.Int, *big.Int, error) {
	dh.createParams()
	A, a, err := diffie.CreateDHPublicKey(dh.p, dh.g)
	if err != nil {
		return nil, nil, nil, err
	}
	dh.myKey = a
	return dh.p, dh.g, A, nil
}

func (dh *DHProtocolUser) ReceiveKeyAndParams(p, g, key *big.Int) {
	dh.p = p
	dh.g = g
	dh.theirKey = key
}

func (dh *DHProtocolUser) SendKey() (*big.Int, error) {
	A, a, err := diffie.CreateDHPublicKey(dh.p, dh.g)
	if err != nil {
		return nil, err
	}
	dh.myKey = a
	dh.createSharedKey()
	return A, nil
}

func (dh *DHProtocolUser) ReceiveKey(key *big.Int) {
	dh.theirKey = key
	dh.createSharedKey()
}

func (dh *DHProtocolUser) SendParams() (*big.Int, *big.Int) {
	dh.createParams()
	return dh.p, dh.g
}

func (dh *DHProtocolUser) ReceiveParams(p, g *big.Int) {
	dh.p = p
	dh.g = g
}

func (dh *DHProtocolUser) SendMessage() ([]byte, []byte) {
	plaintext := []byte("Hello, I'm " + dh.Name)
	iv := RandomKey()
	return ciphers.EncryptAESCBC(plaintext, dh.shared, iv), iv
}

func (dh *DHProtocolUser) ReceiveMessage(ciphertext, iv []byte) {
	plaintext := ciphers.DecryptAESCBC(ciphertext, dh.shared, iv)
	fmt.Printf("%s received: %q\n", dh.Name, plaintext)
}

// Stupid easy passwords that can be brute-forced in reasonable time
func RandomHumanKey() (string, error) {
	passwordNum := rand.Intn(10000)
	var key string
	i := 0
	err := utils.PasswordGenerator(func(password string) bool {
		if i == passwordNum {
			key = password
			return true
		}
		i += 1
		return false
	})
	if err != nil {
		return "", nil
	}
	return key, nil
}

func InitializeSRPWithUnknownPassword() (*diffie.SRPClient, error) {
	key, err := RandomHumanKey()
	if err != nil {
		return nil, err
	}
	client := diffie.NewSRPClient("name@email.com", key)
	err = client.Initialize()
	if err != nil {
		return nil, err
	}
	return client, nil
}

func RSAEncryptKnownPlaintext(plaintext []byte) (string, *big.Int, error) {
	e, _, n, err := ciphers.RSAKeygen(512)
	if err != nil {
		return "", nil, err
	}
	ciphertext := ciphers.RSAEncrypt(plaintext, e, n)
	return ciphertext, n, nil
}
