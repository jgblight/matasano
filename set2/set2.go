package main

import (
  "fmt"
  "io/ioutil"
  "encoding/base64"
  "encoding/hex"
  "errors"

  "github.com/fatih/color"
  "github.com/jgblight/matasano/pkg/utils"
  "github.com/jgblight/matasano/pkg/ciphers"
  "github.com/jgblight/matasano/pkg/secrets"
  "github.com/jgblight/matasano/pkg/hacks"
)

const (
  dataDir = "/Users/jennifer/go/src/github.com/jgblight/matasano/data/"
)

func problemOne(input string) string {
  return string(ciphers.PKCS7([]byte(input), 20))
}

func problemTwo(input string) (string, error) {
  key := []byte("YELLOW SUBMARINE")
  iv := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

  samplePlaintext := "It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife."
  fmt.Printf(" Plaintext: %s\n", samplePlaintext)
  ciphertext := ciphers.EncryptAESCBC([]byte(samplePlaintext), key, iv)
  fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
  plaintext := ciphers.DecryptAESCBC(ciphertext, key, iv)
  fmt.Printf(" Plaintext: %s\n", plaintext[:len(samplePlaintext)])

  text, err := ioutil.ReadFile(dataDir + input)
  if err != nil {
      return "", err
  }

  bytes, err := base64.StdEncoding.DecodeString(string(text))
  if err != nil {
      return "", err
  }

  return string(ciphers.DecryptAESCBC(bytes, key, iv)), nil
}

func problemThree() {
  plaintext := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  for i := 0; i < 15; i++ {
    ciphertext, cipher := secrets.ECBorCBC(plaintext)
    predictedCipher := "CBC"
    if hacks.IsECB(ciphertext, 16) {
      predictedCipher = "ECB"
    }
    fmt.Printf("Encrypted: %s, Detected: %s\n", cipher, predictedCipher)
  }
}

func problemFour() (string, error) {
  blockSize := 2
  encrypted, err := secrets.ECBOracle(utils.MakeRepeatChar('a', blockSize*2))
  if err != nil {
    return "", err
  }
  for !hacks.IsECB(encrypted, blockSize) {
    blockSize++
    encrypted, err = secrets.ECBOracle(utils.MakeRepeatChar('a', blockSize*2))
    if err != nil {
      return "", err
    }
  }
  fmt.Printf("Detected ECB with block size %d\n", blockSize)

  prefix := utils.MakeRepeatChar('a', blockSize - 1)
  decrypted := []byte{}
  for i := 0; i < len(encrypted); i+=blockSize {
    blockStart := i + 16
    block := []byte{}
    for j := 0; j < blockSize; j++ {
      for k := 0; k < 256; k++ {
          attempt := append(prefix, block...)
          attempt = append(attempt, byte(k))
          attempt = append(attempt, prefix...)
          encrypted, err := secrets.ECBOracle(attempt)
          if err != nil {
            return "", err
          }
          firstBlock := encrypted[:blockSize]
          decryptionBlock := encrypted[blockStart:blockStart+blockSize]
          if utils.HammingDistance(firstBlock, decryptionBlock) == 0 {
            decrypted = append(decrypted, byte(k))
            block = append(block, byte(k))
            if len(prefix) > 1 {
              prefix = prefix[1:]
            } else {
              prefix = []byte{}
            }
            break
          }
      }
    }
    if len(block) > 0 {
      prefix = block[1:]
    }
  }
  return string(decrypted), nil
}

func problemFive() error {
  encrypted := secrets.ProfileFor("1234567890123")
  encryptedBytes, err := hex.DecodeString(encrypted)
  roleByte := encryptedBytes[16:32]

  encrypted = secrets.ProfileFor("foo@br.comadmin")
  encryptedBytes, err = hex.DecodeString(encrypted)
  emailByte := encryptedBytes[:16]
  adminByte := encryptedBytes[16:32]

  cutPaste := []byte{}
  cutPaste = append(cutPaste, emailByte...)
  cutPaste = append(cutPaste, roleByte...)
  cutPaste = append(cutPaste, adminByte...)
  cutPaste = append(cutPaste, emailByte...)
  decrypted, err := secrets.DecryptProfile(hex.EncodeToString(cutPaste))
  if err != nil {
    return err
  }
  fmt.Println(decrypted)
  fmt.Printf("Role is: %s\n", decrypted["role"])
  return nil
}

func problemSix() (string, error) {
  blockSize := 16
  padding := utils.MakeRepeatChar('a', blockSize*2)
  encrypted, err := secrets.ECBOracleWithPrefix(padding)
  if err != nil {
    return "", err
  }
  for !hacks.IsECB(encrypted, blockSize) {
    padding = append(padding, 'a')
    encrypted, err = secrets.ECBOracleWithPrefix(padding)
    if err != nil {
      return "", err
    }
  }

  attackStart := 0
  for i := 0; i < len(encrypted) - 16; i++ {
    if utils.HammingDistance(encrypted[i:i+16], encrypted[i+16:i+32]) == 0 {
      attackStart = i+32
      break
    }
  }
  if attackStart == 0 {
    return "", errors.New("Padding failed")
  }

  prefix := utils.MakeRepeatChar('a', blockSize - 1)
  decrypted := []byte{}
  for i := attackStart; i < len(encrypted); i+=blockSize {
    blockStart := i + 16
    block := []byte{}
    for j := 0; j < blockSize; j++ {
      for k := 0; k < 256; k++ {
          attempt := append(padding, prefix...)
          attempt = append(attempt, block...)
          attempt = append(attempt, byte(k))
          attempt = append(attempt, prefix...)
          encrypted, err := secrets.ECBOracleWithPrefix(attempt)
          if err != nil {
            return "", err
          }
          firstBlock := encrypted[attackStart:attackStart+blockSize]
          decryptionBlock := encrypted[blockStart:blockStart+blockSize]
          if utils.HammingDistance(firstBlock, decryptionBlock) == 0 {
            decrypted = append(decrypted, byte(k))
            block = append(block, byte(k))
            if len(prefix) > 1 {
              prefix = prefix[1:]
            } else {
              prefix = []byte{}
            }
            break
          }
      }
    }
    if len(block) > 0 {
      prefix = block[1:]
    }
  }
  return string(decrypted), nil
}

func problemSeven() {
  checkStrings := []string{
    "ICE ICE BABY\x04\x04\x04\x04",
    "ICE ICE BABY\x05\x05\x05\x05\x05",
    "YELLOW SUBMARINE",
    "ICE ICE BABY\x01\x02\x03\x04",
  }

  for _, str := range checkStrings {
    fmt.Printf(" Input: %q\n", str)
    output, err := ciphers.CheckPKCS7([]byte(str))
    if err != nil {
      fmt.Println(" Throws Error")
    } else {
      fmt.Printf(" Output: %q\n", string(output))
    }
  }
}

func problemEight() {
  ciphertext, err := hex.DecodeString(secrets.ParamGenerator(string(utils.MakeRepeatChar('a', 32))))
  if err != nil {
    fmt.Println(err)
  }
  fmt.Printf("Original Ciphertext: %s\n", hex.EncodeToString(ciphertext))

  goalString := []byte("aaaa;admin=true;")

  c1 := ciphertext[32:48]
  p2prime := utils.XOR(c1, utils.MakeRepeatChar('a', 16))
  magicString := utils.XOR(p2prime, goalString)

  for i := 0; i < 16; i++ {
    ciphertext[32+i] = magicString[i]
  }


  fmt.Printf("Modified Ciphertext: %s\n", hex.EncodeToString(ciphertext))
  success, err := secrets.CheckIsAdmin(hex.EncodeToString(ciphertext))
  if err != nil {
    fmt.Println(err)
  }
  fmt.Printf("Is Admin: %v\n", success)
}

func main() {
    header := color.New(color.FgCyan, color.Bold)

    header.Println("Problem 1: Implement PKCS#7 padding")
    input := "YELLOW SUBMARINE"
    fmt.Printf("          Input: %s\n", input)
    output := problemOne(input)
    fmt.Printf("Expected Output: %q\n", "YELLOW SUBMARINE\x04\x04\x04\x04")
    fmt.Printf("  Actual Output: %q\n\n", output)

    header.Println("Problem 2: Implement AES CBC mode")
    input = "set2challenge10.txt"
    output, err := problemTwo(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("         Input: %s\n", input)
    fmt.Printf("        Output: %s\n\n", output)

    header.Println("Problem 3: Construct and ECB detection oracle")
    problemThree()
    fmt.Println()

    header.Println("Problem 4: Byte-at-a-time Decryption")
    output, err = problemFour()
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("        Output: %s\n\n", output)

    header.Println("Problem 5: ECB Cut-and-Paste")
    err = problemFive()
    if err != nil {
      fmt.Println(err)
    }
    fmt.Println()

    header.Println("Problem 6: Byte-at-a-time Decryption (Hard)")
    output, err = problemSix()
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("        Output: %s\n\n", output)


    header.Println("Problem 7: PKCS#7 Padding Validation")
    problemSeven()
    fmt.Println()

    header.Println("Problem 8: CBC Bitflipping Attack")
    problemEight()
    fmt.Println()
  }
