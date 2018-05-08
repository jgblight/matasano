package secrets

import (
	"encoding/hex"
	"errors"
	"math/rand"
	"strings"

	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/utils"
)

const (
	dataDir = "/Users/jennifer/go/src/github.com/jgblight/matasano/data/"
)

func GetCTREncryptedText() ([]byte, error) {
	rand.Seed(7)

	secretKey := RandomKey()
	nonce := rand.Intn(256)

	ciphertext, err := utils.ReadB64File(dataDir + "set1challenge7.txt")
	if err != nil {
		return nil, err
	}
	plaintext := ciphers.DecryptAES(ciphertext, []byte("YELLOW SUBMARINE"))
	return ciphers.CTR(plaintext, secretKey, nonce), nil
}

func Decrypt(text []byte) []byte {
	rand.Seed(7)

	secretKey := RandomKey()
	nonce := rand.Intn(256)
	return ciphers.CTR(text, secretKey, nonce)
}

func EditCiphertext(ciphertext []byte, offset int, plaintext []byte) []byte {
	rand.Seed(7)

	secretKey := RandomKey()
	nonce := rand.Intn(256)
	return ciphers.EditCTR(ciphertext, secretKey, nonce, offset, plaintext)
}

func CTRParamGenerator(userdata string) string {
	rand.Seed(8)
	secretKey := RandomKey()
	nonce := rand.Intn(256)
	dataClean := strings.Replace(userdata, "=", "%3D", -1)
	dataClean = strings.Replace(dataClean, "=", "%3B", -1)
	outputStr := strings.Join([]string{"comment1=cooking%20MCs;userdata=", dataClean, ";comment2=%20like%20a%20pound%20of%20bacon"}, "")
	return hex.EncodeToString(ciphers.CTR([]byte(outputStr), secretKey, nonce))
}

func CTRCheckIsAdmin(ciphertext string) (bool, error) {
	rand.Seed(8)
	secretKey := RandomKey()
	nonce := rand.Intn(256)
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return false, err
	}
	decrypted := ciphers.CTR(decoded, secretKey, nonce)
	return strings.Contains(string(decrypted), ";admin=true;"), nil
}

func DumbIVParamGenerator(userdata string) string {
	rand.Seed(9)
	secretKey := RandomKey()
	dataClean := strings.Replace(userdata, "=", "%3D", -1)
	dataClean = strings.Replace(dataClean, "=", "%3B", -1)
	outputStr := strings.Join([]string{"comment1=cooking%20MCs;userdata=", dataClean, ";comment2=%20like%20a%20pound%20of%20bacon"}, "")
	return hex.EncodeToString(ciphers.EncryptAESCBC([]byte(outputStr), secretKey, secretKey))
}

func DumbIVCheckIsAdmin(ciphertext string) (bool, error) {
	rand.Seed(9)
	secretKey := RandomKey()
	decoded, err := hex.DecodeString(ciphertext)
	if err != nil {
		return false, err
	}
	decrypted := ciphers.DecryptAESCBC(decoded, secretKey, secretKey)
	for _, b := range decrypted {
		if b > byte(127) {
			return false, errors.New(string(decrypted))
		}
	}
	return strings.Contains(string(decrypted), ";admin=true;"), nil
}

func GenerateMAC() ([]byte, string) {
	rand.Seed(10)
	secretKey := RandomKey()
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	return message, hashes.SHA1MAC(secretKey, message)
}

func ValidateIsAdmin(message []byte, theirMAC string) (bool, error) {
	rand.Seed(10)
	secretKey := RandomKey()
	ourMAC := hashes.SHA1MAC(secretKey, message)
	if ourMAC != theirMAC {
		return false, errors.New("Could not validate message")
	}
	return strings.Contains(string(message), ";admin=true"), nil
}

func GenerateMD4MAC() ([]byte, string) {
	rand.Seed(11)
	secretKey := RandomKey()
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	return message, hashes.MD4MAC(secretKey, message)
}

func ValidateMD4IsAdmin(message []byte, theirMAC string) (bool, error) {
	rand.Seed(11)
	secretKey := RandomKey()
	ourMAC := hashes.MD4MAC(secretKey, message)
	if ourMAC != theirMAC {
		return false, errors.New("Could not validate message")
	}
	return strings.Contains(string(message), ";admin=true"), nil
}
