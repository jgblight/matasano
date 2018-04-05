package secrets

import (
  "encoding/hex"
  "encoding/base64"
  "fmt"
  "math/rand"
  "strings"

  "github.com/jgblight/matasano/pkg/ciphers"
)

func RandomKey() []byte {
  key := make([]byte, 16)
  for i := 0; i < 16; i++ {
    key[i] = byte(rand.Intn(256))
  }
  return key
}


func ECBorCBC(input []byte) ([]byte, string) {
  key := RandomKey()
  prefix := make([]byte, 5+rand.Intn(6))
  for i := 0; i < len(prefix); i++ {
    prefix[i] = byte(rand.Intn(256))
  }
  suffix := make([]byte, 5+rand.Intn(6))
  for i := 0; i < len(suffix); i++ {
    suffix[i] = byte(rand.Intn(256))
  }
  plaintext := append(prefix, input...)
  plaintext = append(plaintext, suffix...)

  if rand.Intn(2) == 0 {
    return ciphers.EncryptAES(plaintext, key), "ECB"
  } else {
    iv := RandomKey()
    return ciphers.EncryptAESCBC(plaintext, key, iv), "CBC"
  }
}

func ECBOracle(input []byte) ([]byte, error) {
  rand.Seed(0)
  secretKey := RandomKey()
  secretText, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
  if err != nil {
      return nil, err
  }
  return ciphers.EncryptAES(append(input, secretText...), secretKey), nil
}

func ECBOracleWithPrefix(input []byte) ([]byte, error) {
  rand.Seed(0)
  secretKey := RandomKey()
  secretText, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
  if err != nil {
      return nil, err
  }

  prefixLength := rand.Intn(50) + 5
  text := make([]byte, prefixLength)
  for i := 0; i < prefixLength; i++ {
    text[i] = byte(rand.Intn(256))
  }

  text = append(text, input...)
  text = append(text, secretText...)

  return ciphers.EncryptAES(text, secretKey), nil
}

func paramParser(params string) map[string]string {
  keyValues := strings.Split(params, "&")
  obj := make(map[string]string)
  for _, keyValue := range keyValues {
    values := strings.Split(keyValue, "=")
    obj[values[0]] = values[1]
  }
  return obj
}

func ProfileFor(email string) string {
  emailClean := strings.Replace(email, "&", "", -1)
  emailClean = strings.Replace(emailClean, "=", "", -1)

  outputStr := fmt.Sprintf("email=%s&uid=10&role=user", emailClean)

  rand.Seed(1)
  secretKey := RandomKey()
  return hex.EncodeToString(ciphers.EncryptAES([]byte(outputStr), secretKey))
}

func DecryptProfile(ciphertext string) (map[string]string, error) {
  rand.Seed(1)
  secretKey := RandomKey()
  decoded, err := hex.DecodeString(ciphertext)
  if err != nil {
    return nil, err
  }
  params := ciphers.DecryptAES(decoded, secretKey)

  return paramParser(string(params)), nil
}

func ParamGenerator(userdata string) string {
  rand.Seed(2)
  secretKey := RandomKey()
  iv := RandomKey()
  dataClean := strings.Replace(userdata, "=", "%3D", -1)
  dataClean = strings.Replace(dataClean, "=", "%3B", -1)
  outputStr := strings.Join([]string{"comment1=cooking%20MCs;userdata=",dataClean,";comment2=%20like%20a%20pound%20of%20bacon"}, "")
  return hex.EncodeToString(ciphers.EncryptAESCBC([]byte(outputStr), secretKey, iv))
}

func CheckIsAdmin(ciphertext string) (bool, error) {
  rand.Seed(2)
  secretKey := RandomKey()
  iv := RandomKey()
  decoded, err := hex.DecodeString(ciphertext)
  if err != nil {
    return false, err
  }
  decrypted := ciphers.DecryptAESCBC(decoded, secretKey, iv)
  return strings.Contains(string(decrypted), ";admin=true;"), nil
}
