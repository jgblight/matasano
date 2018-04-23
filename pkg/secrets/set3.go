package secrets

import (
	"encoding/base64"
	"math/rand"
	"time"

	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/rng"
)

func CBCRandomString() ([]byte, []byte, error) {
	rand.Seed(3)

	secretKey := RandomKey()
	iv := RandomKey()

	possibleStrings := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	randomString := possibleStrings[rand.Intn(len(possibleStrings))]
	plaintext, err := base64.StdEncoding.DecodeString(randomString)
	if err != nil {
		return nil, nil, err
	}

	return ciphers.EncryptAESCBC(plaintext, secretKey, iv), iv, nil
}

func HasValidPadding(ciphertext, iv []byte) bool {
	rand.Seed(3)

	secretKey := RandomKey()
	plaintext := ciphers.DecryptAESCBC(ciphertext, secretKey, iv)

	_, err := ciphers.CheckPKCS7(plaintext)
	if err != nil {
		return false
	}
	return true
}

func FixedNonceCTR() ([][]byte, error) {
	rand.Seed(4)

	secretKey := RandomKey()
	nonce := rand.Intn(256)

	encodedSecrets := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}

	encryptedSecrets := make([][]byte, len(encodedSecrets))
	for i, secret := range encodedSecrets {
		plaintext, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return nil, err
		}
		encryptedSecrets[i] = ciphers.CTR(plaintext, secretKey, nonce)
	}

	return encryptedSecrets, nil
}

func RandomNumber() (uint32, time.Time) {
	rand.Seed(5)
	currentTime := time.Now()
	currentTime = currentTime.Add(time.Duration(rand.Intn(960) + 40))
	mt := rng.New(uint32(currentTime.Unix()))
	currentTime = currentTime.Add(time.Duration(rand.Intn(960) + 40))
	return mt.Next(), currentTime
}

func EncryptMT19937CTR(plaintext []byte) []byte {
	rand.Seed(6)
	n := rand.Intn(20) + 5
	prefix := make([]byte, n)
	for i := 0; i < n; i++ {
		prefix[i] = byte(rand.Intn(256))
	}
	plaintext = append(prefix, plaintext...)
	seed := rand.Intn(65536)
	return ciphers.MT19937CTR(plaintext, seed)
}

func PasswordResetToken() []byte {
	mt := rng.New(uint32(time.Now().Unix()))
	return mt.Stream(16)
}
