package hashes

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strconv"

	"github.com/jgblight/matasano/pkg/utils"
)

func parseHex(s string) uint32 {
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		panic(err) // I'm lazy
	}
	return uint32(n)
}

func makeWords(chunk []byte) []uint32 {
	words := make([]uint32, len(chunk)/4)
	for i := 0; i < len(chunk); i += 4 {
		word := chunk[i : i+4]
		words[i/4] = binary.BigEndian.Uint32(word)
	}
	return words
}

func makeLittleWords(chunk []byte) []uint32 {
	words := make([]uint32, len(chunk)/4)
	for i := 0; i < len(chunk); i += 4 {
		word := chunk[i : i+4]
		words[i/4] = binary.LittleEndian.Uint32(word)
	}
	return words
}

func intToWord(i uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return buf
}

func GeneratePadding(l int) []byte {
	m1 := l * 8
	m1Bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(m1Bytes, uint64(m1))

	padding := []byte("\x80")
	requiredBytes := 64 - ((l + 9) % 64)
	padding = append(padding, utils.MakeRepeatChar('\x00', requiredBytes)...)
	padding = append(padding, m1Bytes...)

	return padding
}

func ExtendSHA1(h0, h1, h2, h3, h4 uint32, text []byte) string {
	for i := 0; i < len(text); i += 64 {
		chunk := text[i : i+64]
		w := make([]uint32, 80)
		copy(w[:16], makeWords(chunk))
		for j := 16; j < 80; j++ {
			w[j] = bits.RotateLeft32(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1)
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		for j := 0; j < 80; j++ {
			var f, k uint32
			if j < 20 {
				f = (b & c) | ((^b) & d)
				k = parseHex("5A827999")
			} else if j < 40 {
				f = b ^ c ^ d
				k = parseHex("6ED9EBA1")
			} else if j < 60 {
				f = (b & c) | (b & d) | (c & d)
				k = parseHex("8F1BBCDC")
			} else {
				f = b ^ c ^ d
				k = parseHex("CA62C1D6")
			}
			temp := bits.RotateLeft32(a, 5) + f + e + k + w[j]
			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = temp
		}

		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
	}

	hh := make([]byte, 20)
	copy(hh[:4], intToWord(h0))
	copy(hh[4:8], intToWord(h1))
	copy(hh[8:12], intToWord(h2))
	copy(hh[12:16], intToWord(h3))
	copy(hh[16:], intToWord(h4))
	return hex.EncodeToString(hh)
}

func SHA1(text []byte) string {
	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xEFCDAB89
	var h2 uint32 = 0x98BADCFE
	var h3 uint32 = 0x10325476
	var h4 uint32 = 0xC3D2E1F0

	extendedText := append(text, GeneratePadding(len(text))...)
	return ExtendSHA1(h0, h1, h2, h3, h4, extendedText)
}

func SHA1MAC(key, message []byte) string {
	return SHA1(append(key, message...))
}

func HMACSHA1(key, message []byte) string {
	if len(key) < 64 {
		key = append(key, utils.MakeRepeatChar('\x00', 64-len(key))...)
	}

	oKeyPad := utils.XOR(key, utils.MakeRepeatChar('\x5c', 64))
	iKeyPad := utils.XOR(key, utils.MakeRepeatChar('\x36', 64))

	hash1, _ := hex.DecodeString(SHA1(append(iKeyPad, message...)))
	return SHA1(append(oKeyPad, hash1...))
}

func GenerateMD4Padding(l int) []byte {
	m1 := l * 8
	m1Bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(m1Bytes, uint64(m1))

	padding := []byte("\x80")
	requiredBytes := 64 - ((l + 9) % 64)
	padding = append(padding, utils.MakeRepeatChar('\x00', requiredBytes)...)
	padding = append(padding, m1Bytes...)

	return padding
}

func ExtendMD4(a, b, c, d uint32, text []byte) string {
	shift1 := []uint{3, 7, 11, 19}
	shift2 := []uint{3, 5, 9, 13}
	shift3 := []uint{3, 9, 11, 15}

	xIndex2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	xIndex3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

	for i := 0; i < len(text); i += 64 {
		chunk := text[i : i+64]
		w := make([]uint32, 16)
		copy(w, makeLittleWords(chunk))

		aa := a
		bb := b
		cc := c
		dd := d

		for j := 0; j < 16; j++ {
			s := shift1[j%4]
			x := j
			f := ((c ^ d) & b) ^ d
			a += f + w[x]
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		for j := 0; j < 16; j++ {
			s := shift2[j%4]
			x := xIndex2[j]
			f := (b & c) | (b & d) | (c & d)
			a += f + w[x] + 0x5A827999
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		for j := 0; j < 16; j++ {
			s := shift3[j%4]
			x := xIndex3[j]
			f := b ^ c ^ d
			a += f + w[x] + 0x6ED9EBA1
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		a = a + aa
		b = b + bb
		c = c + cc
		d = d + dd
	}

	hh := []byte{}
	for _, i := range []uint32{a, b, c, d} {
		hh = append(hh, byte(i>>0))
		hh = append(hh, byte(i>>8))
		hh = append(hh, byte(i>>16))
		hh = append(hh, byte(i>>24))
	}
	return hex.EncodeToString(hh)
}

func MD4(text []byte) string {
	extendedText := append(text, GenerateMD4Padding(len(text))...)

	var a uint32 = 0x67452301
	var b uint32 = 0xEFCDAB89
	var c uint32 = 0x98BADCFE
	var d uint32 = 0x10325476

	return ExtendMD4(a, b, c, d, extendedText)
}

func MD4MAC(key, message []byte) string {
	return MD4(append(key, message...))
}
