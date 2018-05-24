package utils

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math"
	"math/big"
	"math/bits"
	"os"
)

const (
	dataDir   = "/Users/jennifer/go/src/github.com/jgblight/matasano/data/"
	NISTPrime = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
)

func GetNISTPrime() *big.Int {
	x := &big.Int{}
	x.SetString(NISTPrime, 16)
	return x
}

func GetBigInt(i int) *big.Int {
	x := &big.Int{}
	x.SetInt64(int64(i))
	return x
}

func IntMin(a, b int) int {
	return int(math.Min(float64(a), float64(b)))
}

func frequencyMap() map[byte]float64 {
	return map[byte]float64{
		'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
		'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
		'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
		'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
		'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
		'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
		'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
}

func ReadB64File(filename string) ([]byte, error) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	bytes, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func Readln(r *bufio.Reader) (string, error) {
	var (
		isPrefix bool  = true
		err      error = nil
		line, ln []byte
	)
	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}
	return string(ln), err
}

func XOR(bufOne, bufTwo []byte) []byte {
	outputBytes := make([]byte, len(bufOne), len(bufTwo))
	for i := 0; i < len(bufOne); i++ {
		outputBytes[i] = bufOne[i] ^ bufTwo[i]
	}
	return outputBytes
}

func MakeRepeatChar(char byte, length int) []byte {
	outputBytes := make([]byte, length, length)
	for i := 0; i < length; i++ {
		outputBytes[i] = char
	}
	return outputBytes
}

func MakeRepeatKey(key []byte, length int) []byte {
	pos := 0
	outputBytes := make([]byte, length, length)
	for i := 0; i < length; i++ {
		outputBytes[i] = key[pos]
		pos++
		if pos >= len(key) {
			pos = 0
		}
	}
	return outputBytes
}

func CharacterScore(input []byte) float64 {
	strLength := len(input)
	lower := bytes.ToLower(input)
	charCounts := make(map[byte]int)

	freqMap := frequencyMap()

	chi2 := 0.
	for i := 0; i < strLength; i++ {
		char := lower[i]
		c := int(char)
		if (c >= 32 && c <= 126) || c == 9 || c == 10 || c == 13 {
			if freqMap[char] > 0 {
				charCounts[char]++
			} else {
				chi2 += 10. // punctuation
			}
		} else {
			chi2 += 1000. // improbable character
		}
	}

	for char, freq := range freqMap {
		expectedCount := freq * float64(strLength)
		delta := (float64(charCounts[char]) - expectedCount)
		chi2 += delta * delta / expectedCount
	}
	return chi2
}

func HammingDistance(strOne, strTwo []byte) int {
	length := len(strOne)
	distance := 0
	for i := 0; i < length; i++ {
		diff := strOne[i] ^ strTwo[i]
		distance += bits.OnesCount(uint(diff))
	}
	return distance
}

func CreateMask(l, r uint32) uint32 {
	var mask uint32 = 0
	for i := l; i < r; i++ {
		if i < 32 {
			mask = mask + (1 << (31 - i))
		}
	}
	return mask
}

func PasswordGenerator(fn func(string) bool) error {
	f, err := os.Open(dataDir + "common_passwords.txt")
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		str := scanner.Text()
		shouldBreak := fn(str)
		if shouldBreak {
			return nil
		}
	}
	return nil
}

func HexToBigint(text string) (*big.Int, error) {
	cBytes, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(cBytes), nil
}
