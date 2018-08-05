package secrets

import (
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/hashes"
)

type RSAServer struct {
	E *big.Int
	d *big.Int
	N *big.Int

	seen map[string]bool
}

func NewRSAServer(keyLength int) (*RSAServer, error) {
	e, d, n, err := ciphers.RSAKeygen(keyLength)
	if err != nil {
		return nil, err
	}
	return &RSAServer{E: e, d: d, N: n, seen: make(map[string]bool)}, nil
}

func (s *RSAServer) DecryptMessage(ciphertext string) ([]byte, error) {
	hash := hashes.SHA1([]byte(ciphertext))
	if s.seen[hash] {
		return nil, errors.New("cannot resubmit message")
	}
	s.seen[hash] = true
	return ciphers.RSADecrypt(ciphertext, s.d, s.N)
}

func GetClientMessage(server *RSAServer) (string, error) {
	plaintext := []byte("I am a plaintext message")
	encrypted := ciphers.RSAEncrypt(plaintext, server.E, server.N)
	_, err := server.DecryptMessage(encrypted)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

func (s *RSAServer) CheckIsEven(ciphertext string) (bool, error) {
	plaintext, err := ciphers.RSADecrypt(ciphertext, s.d, s.N)
	if err != nil {
		return false, err
	}
	lastByte := plaintext[len(plaintext)-1]
	if int(lastByte)%2 == 0 {
		return true, nil
	}
	return false, nil
}

func GetClientMessage2(server *RSAServer) (string, error) {
	plaintext, err := base64.StdEncoding.DecodeString("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
	if err != nil {
		return "", err
	}
	encrypted := ciphers.RSAEncrypt(plaintext, server.E, server.N)
	_, err = server.DecryptMessage(encrypted)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

func (s *RSAServer) PKCS15Valid(ciphertext string) (bool, error) {
	plaintext, err := ciphers.RSADecrypt(ciphertext, s.d, s.N)
	if err != nil {
		return false, err
	}
	k := s.N.BitLen() / 8
	if len(plaintext) == k-1 {
		plaintext = append([]byte("\x00"), plaintext...)
	}
	if int(plaintext[0]) == 0 && int(plaintext[1]) == 2 {
		return true, nil
	}
	return false, nil
}

func GetClientMessage3(server *RSAServer) (string, error) {
	plaintext := []byte("kick it, CC")
	encrypted := ciphers.PKCS15Encrypt(plaintext, server.E, server.N)
	_, err := server.DecryptMessage(encrypted)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

func GetClientMessage4(server *RSAServer) (string, error) {
	plaintext := []byte("And I'm never gonna stop until I make 'em drop and burn 'em up and scatter their remains")
	encrypted := ciphers.PKCS15Encrypt(plaintext, server.E, server.N)
	_, err := server.DecryptMessage(encrypted)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}
