package main

import (
  "bufio"
  "encoding/hex"
  "encoding/base64"
  "fmt"
  "io/ioutil"
  "os"

  "github.com/fatih/color"
  "github.com/jgblight/matasano/pkg/utils"
  "github.com/jgblight/matasano/pkg/ciphers"
)

const (
  dataDir = "/Users/jennifer/go/src/github.com/jgblight/matasano/data/"
)

func problemOne(input string) (string, error) {
    bytes, err := hex.DecodeString(input)
    if err != nil {
      return "", err
    }
    return base64.StdEncoding.EncodeToString(bytes), nil
}

func problemTwo(inputOne, inputTwo string) (string, error) {
  bytesOne, err := hex.DecodeString(inputOne)
  if err != nil {
    return "", err
  }

  bytesTwo, err := hex.DecodeString(inputTwo)
  if err != nil {
    return "", err
  }

  return hex.EncodeToString(utils.XOR(bytesOne, bytesTwo)), nil
}

func problemThree(input string) (string, error) {
    bytes, err := hex.DecodeString(input)
    if err != nil {
      return "", err
    }
    result, _, _ := ciphers.DecryptSingleByteXOR(bytes)
    return string(result), nil
}

func problemFour(input string) (string, error) {
  f, err := os.Open(dataDir + input)
  if err != nil {
      return "", err
  }
  scanner := bufio.NewScanner(f)

  bestScore := 10000.
  var bestResult []byte
  for scanner.Scan() {
    str := scanner.Text()
    bytes, err := hex.DecodeString(str)
    if err != nil {
      return "", err
    }
    result, _, score := ciphers.DecryptSingleByteXOR(bytes)
    if score < bestScore {
      bestScore = score
      bestResult = result
    }
  }
  return string(bestResult), nil
}

func problemFive(input string) string {
  bytes := []byte(input)
  encrypted := ciphers.RepeatingKeyXOR(bytes, []byte("ICE"))
  return hex.EncodeToString(encrypted)
}

func problemSix(input string) (string, string, error) {
  text, err := ioutil.ReadFile(dataDir + input)
  if err != nil {
      return "", "", err
  }

  bytes, err := base64.StdEncoding.DecodeString(string(text))
  if err != nil {
      return "", "", err
  }

  plaintext, key := ciphers.BreakRepeatingKeyXOR(bytes)
  return string(plaintext), string(key), nil
}

func problemSeven(input string) (string, error) {
  text, err := ioutil.ReadFile(dataDir + input)
  if err != nil {
      return "", err
  }

  bytes, err := base64.StdEncoding.DecodeString(string(text))
  if err != nil {
      return "", err
  }

  plaintext := ciphers.DecryptAES(bytes, []byte("YELLOW SUBMARINE"))
  return string(plaintext), nil
}

func problemEight(input string) (string, error) {
  f, err := os.Open(dataDir + input)
  if err != nil {
      return "", err
  }
  scanner := bufio.NewScanner(f)

  for scanner.Scan() {
    str := scanner.Text()
    bytes, err := hex.DecodeString(str)
    if err != nil {
      return "", err
    }

    for i := 0; i < len(bytes); i+=16 {
      chunkOne := bytes[i:utils.IntMin(i+16, len(bytes))]
      for j := 0; j < len(bytes); j+= 16 {
        if i == j {
          continue
        }
        chunkTwo := bytes[i:utils.IntMin(i+16, len(bytes))]
        if utils.HammingDistance(chunkOne, chunkTwo) == 0 {
          return str, nil
        }
      }
    }

  }
  return "", nil
}

func main() {
    header := color.New(color.FgCyan, color.Bold)

    header.Println("Problem 1: convert a hex string to base 64")
    input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    fmt.Printf("          Input: %s\n", input)
    output, err := problemOne(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("Expected Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n")
    fmt.Printf("  Actual Output: %s\n\n", output)


    header.Println("Problem 2: XOR two buffers")
    inputOne := "1c0111001f010100061a024b53535009181c"
    inputTwo := "686974207468652062756c6c277320657965"
    fmt.Printf("          Input: %s, %s\n", inputOne, inputTwo)
    output, err = problemTwo(inputOne, inputTwo)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("Expected Output: 746865206b696420646f6e277420706c6179\n")
    fmt.Printf("  Actual Output: %s\n\n", output)

    header.Println("Problem 3: Decrypt single-byte XOR cipher")
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    fmt.Printf("          Input: %s\n", input)
    output, err = problemThree(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("         Output: %s\n\n", output)

    header.Println("Problem 4: Detect single-byte XOR cipher")
    input = "set1challenge4.txt"
    fmt.Printf("          Input: %s\n", input)
    output, err = problemFour(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("         Output: %s\n\n", output)

    header.Println("Problem 5: Repeating Key XOR")
    input = "Burning 'em, if you ain't quick and nimble\n" +
            "I go crazy when I hear a cymbal"
    fmt.Printf("          Input: %s\n", input)
    output = problemFive(input)
    fmt.Printf("Expected Output: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f\n")
    fmt.Printf("         Output: %s\n\n", output)

    header.Println("Problem 6: Decrypt repeating key XOR cipher")
    input = "set1challenge6.txt"
    fmt.Printf("          Input: %s\n", input)
    plaintext, key, err := problemSix(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("         Key: %s\n", key)
    fmt.Printf("   Plaintext: %s\n\n", plaintext)

    header.Println("Problem 7: Decrypt AES in ECB mode")
    input = "set1challenge7.txt"
    fmt.Printf("       Input: %s\n", input)
    plaintext, err = problemSeven(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("   Plaintext: %s\n\n", plaintext)

    header.Println("Problem 8: Detect AES in ECB mode")
    input = "set1challenge8.txt"
    fmt.Printf("    Input: %s\n", input)
    output, err = problemEight(input)
    if err != nil {
      fmt.Println(err)
    }
    fmt.Printf("   Output: %s\n\n", output)
}
