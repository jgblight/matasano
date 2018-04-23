package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/hacks"
	"github.com/jgblight/matasano/pkg/rng"
	"github.com/jgblight/matasano/pkg/secrets"
	"github.com/jgblight/matasano/pkg/utils"
)

const (
	dataDir = "/Users/jennifer/go/src/github.com/jgblight/matasano/data/"
)

func decryptBlock(c1, c2, plaintextBlock, iv []byte, attackChar int) ([]byte, bool) {
	if attackChar < 0 {
		return plaintextBlock, true
	}

	paddingByte := byte(16 - attackChar)
	p2prime := append(utils.MakeRepeatChar(byte(0), attackChar), utils.MakeRepeatChar(paddingByte, int(paddingByte))...)

	c1prime := utils.XOR(c1, utils.XOR(plaintextBlock, p2prime))
	foundChar := false
	foundNextChar := false
	for testChar := 0; testChar < 256; testChar++ {
		c1prime[attackChar] = byte(testChar)
		corruptedText := append(c1prime, c2...)
		if secrets.HasValidPadding(corruptedText, iv) {
			plaintextChar := paddingByte ^ c1prime[attackChar] ^ c1[attackChar]
			plaintextBlock[attackChar] = plaintextChar
			foundChar = true
			plaintextBlock, foundNextChar = decryptBlock(c1, c2, plaintextBlock, iv, attackChar-1)
			if foundNextChar {
				break
			}
		}
	}

	return plaintextBlock, foundChar
}

func problemOne() (string, error) {
	ciphertext, iv, err := secrets.CBCRandomString()
	if err != nil {
		return "", err
	}

	ciphertext = append(iv, ciphertext...)
	plaintext := []byte{}

	for attackStart := 0; attackStart < len(ciphertext)-16; attackStart += 16 {
		c1 := ciphertext[attackStart : attackStart+16]
		c2 := ciphertext[attackStart+16 : attackStart+32]

		plaintextBlock := make([]byte, 16)
		plaintextBlock, _ = decryptBlock(c1, c2, plaintextBlock, iv, 15)
		plaintext = append(plaintext, plaintextBlock...)
	}
	return string(plaintext), nil
}

func problemTwo(input string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	key := []byte("YELLOW SUBMARINE")
	return string(ciphers.CTR(ciphertext, key, 0)), nil
}

func verticalSlice(ciphertexts [][]byte, i int) []byte {
	slice := []byte{}
	for _, text := range ciphertexts {
		if i < len(text) {
			slice = append(slice, text[i])
		}
	}
	return slice
}

func statisticalCTR(ciphertexts [][]byte) {
	keystream := []byte{}
	i := 0
	for slice := verticalSlice(ciphertexts, i); len(slice) > 5; {
		bestScore := 100 * float64(len(slice))
		bestChar := 0
		for testChar := 0; testChar < 256; testChar++ {
			testSlice := utils.XOR(slice, utils.MakeRepeatChar(byte(testChar), len(slice)))
			testScore := utils.CharacterScore(testSlice)
			if testScore < bestScore {
				bestScore = testScore
				bestChar = testChar
			}
		}
		keystream = append(keystream, byte(bestChar))
		i++
		slice = verticalSlice(ciphertexts, i)
	}

	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > len(keystream) {
			decrypted := utils.XOR(ciphertext[:len(keystream)], keystream)
			fmt.Printf("%s...\n", string(decrypted))
		} else {
			decrypted := utils.XOR(ciphertext, keystream[:len(ciphertext)])
			fmt.Printf("%s\n", string(decrypted))
		}
	}
}

func problemThree() error {
	ciphertexts, err := secrets.FixedNonceCTR()
	if err != nil {
		return err
	}

	statisticalCTR(ciphertexts)
	return nil
}

func problemFour(input string) error {
	ciphertexts := [][]byte{}
	f, err := os.Open(dataDir + input)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		str := scanner.Text()
		bytes, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return err
		}
		ciphertexts = append(ciphertexts, bytes)
	}

	statisticalCTR(ciphertexts)
	return nil
}

func problemFive(i uint32) []uint32 {
	mt := rng.New(i)
	output := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		output[i] = mt.Next()
	}
	return output
}

func problemSix() {
	num, now := secrets.RandomNumber()
	ts := now.Unix()
	fmt.Printf("Number: %d\n", num)
	for i := ts - 2000; i <= ts; i++ {
		mt := rng.New(uint32(i))
		if mt.Next() == num {
			fmt.Printf("  Seed: %d\n", i)
			return
		}
	}
	fmt.Print("Seed not found")
}

func problemSeven() {
	mt := rng.New(uint32(time.Now().Unix()))
	values := make([]uint32, 624)
	for i := 0; i < 624; i++ {
		values[i] = hacks.Untemper(mt.Next())
	}
	clonedMT := rng.Clone(values)
	for i := 0; i < 5; i++ {
		v := mt.Next()
		cv := clonedMT.Next()
		match := (v == cv)
		fmt.Printf("Original: %d\tClone: %d\tMatch: %t\n", v, cv, match)
	}
}

func problemEight() {
	fmt.Println("Implement MT19937 Stream Cipher")
	plaintext := utils.MakeRepeatChar('a', 16)
	fmt.Printf("   Plaintext: %q\n", plaintext)
	ciphertext := ciphers.MT19937CTR(plaintext, 256)
	fmt.Printf("  Ciphertext: %q\n", ciphertext)
	fmt.Printf("   Plaintext: %q\n", ciphers.MT19937CTR(ciphertext, 256))
	fmt.Println()

	fmt.Println("Break MT19937 Stream Cipher")
	ciphertext = secrets.EncryptMT19937CTR(plaintext)
	fmt.Printf("  Ciphertext: %q\n", ciphertext)

	lenPrefix := len(ciphertext) - len(plaintext)
	prefixNumbers := (lenPrefix / 4) + 1
	if lenPrefix%4 == 0 {
		prefixNumbers = lenPrefix / 4
	}

	start := prefixNumbers * 4
	knownKeystream := utils.XOR(ciphertext[start:start+12], plaintext)
	knownNumbers := hacks.GetRandomNumbersFromKeystream(knownKeystream)

	seed := 0
	for i := 0; i < 65536; i++ {
		testMT := rng.New(uint32(i))
		for j := 0; j < prefixNumbers; j++ {
			testMT.Next()
		}
		pass := true
		for _, n := range knownNumbers {
			if n != testMT.Next() {
				pass = false
				break
			}
		}
		if pass {
			seed = i
			break
		}
	}

	fmt.Printf("  Found Seed:%d\n", seed)
	fmt.Println()

	fmt.Println("Detect Time-Seeded Password Reset Tokens")
	token := secrets.PasswordResetToken()
	fmt.Printf("  Token %q\n", token)
	fmt.Printf("    Is MT19937 Stream: %t\t Expected: true\n", hacks.IsTokenMT19337Stream(token))
	token = secrets.RandomKey()
	fmt.Printf("  Token %q\n", token)
	fmt.Printf("    Is MT19937 Stream: %t\t Expected: false\n", hacks.IsTokenMT19337Stream(token))
	token = secrets.PasswordResetToken()
	fmt.Printf("  Token %q\n", token)
	fmt.Printf("    Is MT19937 Stream: %t\t Expected: true\n", hacks.IsTokenMT19337Stream(token))
	token = secrets.RandomKey()
	fmt.Printf("  Token %q\n", token)
	fmt.Printf("    Is MT19937 Stream: %t\t Expected: false\n", hacks.IsTokenMT19337Stream(token))

}

func main() {
	header := color.New(color.FgCyan, color.Bold)

	header.Println("Problem 1: CBC Padding Oracle")
	output, err := problemOne()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Output: %q\n\n", output)

	header.Println("Problem 2: Implement CTR")
	input := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	fmt.Printf(" Input: %q\n\n", input)
	output, err = problemTwo(input)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Output: %q\n\n", output)

	header.Println("Problem 3: Break Fixed-Nonce CTR")
	err = problemThree()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 4: Break Fixed-Nonce CTR Again")
	err = problemFour("set3challenge20.txt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 5: Implement Mersenne Twister 19337 RNG")
	inputInt := uint32(5489)
	expected := []uint32{3499211612, 581869302, 3890346734, 3586334585, 545404204}
	fmt.Printf("          Input: %d\n", inputInt)
	actual := problemFive(5489)
	fmt.Printf("Expected Output: %v\n", expected)
	fmt.Printf("  Actual Output: %v\n\n", actual)

	header.Println("Problem 6: Crack a MT19337 Seed")
	problemSix()
	fmt.Println()

	header.Println("Problem 7: Clone a MT19337 RNG")
	problemSeven()
	fmt.Println()

	header.Println("Problem 8: Crack a MT19337 Stream Cipher")
	problemEight()
}
