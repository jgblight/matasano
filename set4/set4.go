package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/secrets"
	"github.com/jgblight/matasano/pkg/server"
	"github.com/jgblight/matasano/pkg/utils"
)

func problemOne() (string, error) {
	ciphertext, err := secrets.GetCTREncryptedText()
	if err != nil {
		return "", err
	}
	knownPlaintext := utils.MakeRepeatChar('a', len(ciphertext))
	editedCiphertext := secrets.EditCiphertext(ciphertext, 0, knownPlaintext)
	keystream := utils.XOR(editedCiphertext, knownPlaintext)
	originalPlaintext := utils.XOR(ciphertext, keystream)
	return string(originalPlaintext), nil
}

func problemTwo() {
	ciphertext, err := hex.DecodeString(secrets.CTRParamGenerator(string(utils.MakeRepeatChar('a', 32))))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Original Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	goalString := []byte("aaaa;admin=true;")

	c1 := ciphertext[32:48]
	keystream := utils.XOR(c1, utils.MakeRepeatChar('a', 16))
	c2 := utils.XOR(keystream, goalString)

	for i := 0; i < 16; i++ {
		ciphertext[32+i] = c2[i]
	}

	fmt.Printf("Modified Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	success, err := secrets.CTRCheckIsAdmin(hex.EncodeToString(ciphertext))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Is Admin: %v\n", success)
}

func problemThree() error {
	ciphertext, err := hex.DecodeString(secrets.DumbIVParamGenerator(string(utils.MakeRepeatChar('a', 32))))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Original Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	c1 := ciphertext[:16]
	attackCiphertext := utils.MakeRepeatChar('\x00', 48)
	copy(attackCiphertext[:16], c1)
	copy(attackCiphertext[32:], c1)

	fmt.Printf("Modified Ciphertext: %s\n", hex.EncodeToString(attackCiphertext))
	_, err = secrets.DumbIVCheckIsAdmin(hex.EncodeToString(attackCiphertext))
	if err == nil {
		return errors.New("Hmmm, that didn't work")
	}
	decrypted := []byte(err.Error())
	recoveredKey := utils.XOR(decrypted[:16], decrypted[32:])
	fmt.Printf("Recovered Key: %q\n", recoveredKey)
	plaintext := []byte("foo=bar;admin=true;comment=whatever")
	ciphertext = ciphers.EncryptAESCBC(plaintext, recoveredKey, recoveredKey)
	success, err := secrets.DumbIVCheckIsAdmin(hex.EncodeToString(ciphertext))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Is Admin: %v\n", success)
	return nil
}

func problemFour() {
	key := secrets.RandomKey()
	message := []byte("The quick brown fox jumps over the lazy dog")
	fmt.Printf("    Key: %q\n", key)
	fmt.Printf("Message: %q\n", message)
	output := hashes.SHA1MAC(key, message)
	fmt.Printf("    MAC: %q\n", output)

	fmt.Println("\nAlter Message")
	message[40] -= 1
	fmt.Printf("    Key: %q\n", key)
	fmt.Printf("Message: %q\n", message)
	output = hashes.SHA1MAC(key, message)
	fmt.Printf("    MAC: %q\n", output)

	fmt.Println("\nAlter Key")
	message[40] += 1
	key[0] += 1
	fmt.Printf("    Key: %q\n", key)
	fmt.Printf("Message: %q\n", message)
	output = hashes.SHA1MAC(key, message)
	fmt.Printf("    MAC: %q\n", output)
}

func problemFive() error {
	message, mac := secrets.GenerateMAC()

	fmt.Printf("Original Message: %q\n", message)
	fmt.Printf("    Original MAC: %q\n", mac)
	hh, err := hex.DecodeString(mac)
	if err != nil {
		return err
	}
	h0 := binary.BigEndian.Uint32(hh[:4])
	h1 := binary.BigEndian.Uint32(hh[4:8])
	h2 := binary.BigEndian.Uint32(hh[8:12])
	h3 := binary.BigEndian.Uint32(hh[12:16])
	h4 := binary.BigEndian.Uint32(hh[16:])

	targetString := []byte(";admin=true")

	for keyLengthGuess := 4; keyLengthGuess < 32; keyLengthGuess++ {
		lengthGuess := keyLengthGuess + len(message)

		gluePadding := hashes.GeneratePadding(lengthGuess)
		endPadding := hashes.GeneratePadding(lengthGuess + len(gluePadding) + len(targetString))
		messageExtension := append(targetString, endPadding...)

		newMac := hashes.ExtendSHA1(h0, h1, h2, h3, h4, messageExtension)
		newMessage := append(message, gluePadding...)
		newMessage = append(newMessage, targetString...)

		isAdmin, err := secrets.ValidateIsAdmin(newMessage, newMac)
		if (err == nil) && (isAdmin) {
			fmt.Printf(" Modifed Message: %q\n", newMessage)
			fmt.Printf("    Modified MAC: %q\n", newMac)
			fmt.Printf("        Is Admin: %v\n", isAdmin)
			return nil
		}
	}
	return errors.New("didn't find the thing")
}

func problemSix() error {
	message, mac := secrets.GenerateMD4MAC()

	fmt.Printf("Original Message: %q\n", message)
	fmt.Printf("    Original MAC: %q\n", mac)
	hh, err := hex.DecodeString(mac)
	if err != nil {
		return err
	}
	a := binary.LittleEndian.Uint32(hh[:4])
	b := binary.LittleEndian.Uint32(hh[4:8])
	c := binary.LittleEndian.Uint32(hh[8:12])
	d := binary.LittleEndian.Uint32(hh[12:])

	targetString := []byte(";admin=true")

	for keyLengthGuess := 4; keyLengthGuess < 32; keyLengthGuess++ {
		lengthGuess := keyLengthGuess + len(message)

		gluePadding := hashes.GenerateMD4Padding(lengthGuess)
		endPadding := hashes.GenerateMD4Padding(lengthGuess + len(gluePadding) + len(targetString))
		messageExtension := append(targetString, endPadding...)

		newMac := hashes.ExtendMD4(a, b, c, d, messageExtension)
		newMessage := append(message, gluePadding...)
		newMessage = append(newMessage, targetString...)

		isAdmin, err := secrets.ValidateMD4IsAdmin(newMessage, newMac)
		if (err == nil) && (isAdmin) {
			fmt.Printf(" Modifed Message: %q\n", newMessage)
			fmt.Printf("    Modified MAC: %q\n", newMac)
			fmt.Printf("        Is Admin: %v\n", isAdmin)
			return nil
		}
	}
	return errors.New("didn't find the thing")
}

func problemSeven() error {
	message := "foo"
	foundHash := ""
	testChars := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
	times := make([]int64, 16)
	for j := 0; j < 40; j++ {
		for i, c := range testChars {
			testHash := foundHash + c + string(utils.MakeRepeatChar('0', 39-len(foundHash)))
			request := fmt.Sprintf("http://localhost:1323/checkHMACSlow?file=%s&signature=%s", message, testHash)
			start := time.Now()
			resp, err := http.Get(request)
			elapsed := time.Since(start)
			if err != nil {
				return err
			}
			if resp.StatusCode == 200 {
				fmt.Printf("Found Hash: %s", testHash)
				return nil
			}
			times[i] = elapsed.Nanoseconds()
		}
		var bestTime int64 = 0
		bestChar := "G"
		for i, t := range times {
			if t > bestTime {
				bestTime = t
				bestChar = testChars[i]
			}
		}
		foundHash = foundHash + bestChar
		fmt.Println(foundHash)
	}

	return nil
}

func stats(numbers []int64) (float64, float64) {
	n := float64(len(numbers))
	sum := 0.0
	for _, x := range numbers {
		sum += float64(x)
	}
	mean := sum / n
	variance := 0.0
	for _, x := range numbers {
		variance += math.Pow(float64(x)-mean, 2)
	}
	variance = variance / (n - 1)
	return mean, math.Sqrt(variance)
}

func problemEight() error {
	message := "foo"
	foundHash := ""
	testChars := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}

	for j := 0; j < 40; j++ {
		times := make([]int64, 16)
		bestScore := 0.0
		bestChar := "G"
		stdDev := 0.0
		mean := 0.0
		tries := 0
		minTries := int(math.Floor(float64(j)*0.1 + 2))
		candidates := 0
		for bestScore < stdDev*2 || candidates > 1 || tries < minTries {
			for i, c := range testChars {
				testHash := foundHash + c + string(utils.MakeRepeatChar('0', 39-len(foundHash)))
				request := fmt.Sprintf("http://localhost:1323/checkHMACFast?file=%s&signature=%s", message, testHash)
				start := time.Now()
				resp, err := http.Get(request)
				elapsed := time.Since(start)
				if err != nil {
					return err
				}
				resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Printf("Found Hash: %s", testHash)
					return nil
				}

				times[i] += elapsed.Nanoseconds()
			}
			mean, stdDev = stats(times)
			candidates = 0
			for i, t := range times {
				score := float64(t) - mean
				if score > stdDev*2 {
					candidates += 1
				}

				if score > bestScore {
					bestScore = score
					bestChar = testChars[i]
				}
			}
			tries++
		}
		foundHash = foundHash + bestChar
		fmt.Println(foundHash)
	}

	return nil
}

func main() {
	header := color.New(color.FgCyan, color.Bold)

	header.Println("Problem 1: Break random access read/write AES CTR")
	output, err := problemOne()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Output: %s\n\n", output)

	header.Println("Problem 2: CTR Bitflipping Attack")
	problemTwo()
	fmt.Println()

	header.Println("Problem 3: Recover Key from CBC when IV=Key")
	err = problemThree()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 4: Implement SHA-1 MAC")
	problemFour()
	fmt.Println()

	header.Println("Problem 5: SHA-1 MAC Length Extension")
	err = problemFive()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 6: MD4 MAC Length Extension")
	err = problemSix()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	go server.StartServer()
	_, _ = http.Get("http://localhost:1323")

	header.Println("Problem 7: HMAC-SHA1 timing attack (slow)")
	err = problemSeven()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 8: HMAC-SHA1 timing attack (fast)")
	err = problemEight()
	if err != nil {
		fmt.Println(err)
	}
}
