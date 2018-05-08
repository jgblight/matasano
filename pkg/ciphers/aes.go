package ciphers

import (
	"encoding/binary"
	"errors"

	"github.com/jgblight/matasano/pkg/utils"
)

func rcon(i int) byte {
	arr := []byte{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a}
	return arr[i]
}

func sbox(i int) byte {
	arr := []byte{
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
	}
	return arr[i]
}

func inv_sbox(i int) byte {
	arr := []byte{
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
	}
	return arr[i]
}

func gmul(a, b byte) byte {
	p := byte(0)

	for c := 0; c < 8; c++ {
		if (b & 1) != 0 {
			p ^= a
		}

		hi_bit_set := (a & 0x80) != 0
		a <<= 1
		if hi_bit_set {
			a ^= 0x1B /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1
	}

	return p
}

func rotate(b []byte) []byte {
	output := make([]byte, 4)
	for i := 0; i < 3; i++ {
		output[i] = b[i+1]
	}
	output[3] = b[0]
	return output
}

func scheduleCore(input []byte, i int) []byte {
	output := rotate(input)
	for j := 0; j < 4; j++ {
		output[j] = sbox(int(output[j]))
	}
	output[0] ^= rcon(i)
	return output
}

func keySchedule(key []byte) [][]byte {
	var keys [][]byte
	keys = append(keys, key)
	i := 1
	lastKey := key
	for x := 0; x < 10; x++ {
		t := make([]byte, 4)
		for y := 0; y < 4; y++ {
			t[y] = lastKey[y+12]
		}
		t = scheduleCore(t, i)
		i++
		var nextKey []byte
		for y := 0; y < 16; y += 4 {
			for z := 0; z < 4; z++ {
				t[z] ^= lastKey[y+z]
			}
			nextKey = append(nextKey, t...)
		}
		keys = append(keys, nextKey)
		lastKey = nextKey
	}
	return keys
}

func matrixify(block []byte) [][]byte {
	matrix := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		matrix[i] = make([]byte, 4)
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			matrix[j][i] = block[i*4+j]
		}
	}
	return matrix
}

func blockify(matrix [][]byte) []byte {
	block := make([]byte, 16)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			block[i*4+j] = matrix[j][i]
		}
	}
	return block
}

func applyRoundKey(block [][]byte, key [][]byte) [][]byte {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			block[i][j] ^= key[i][j]
		}
	}
	return block
}

func subBytes(block [][]byte) [][]byte {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			block[i][j] = sbox(int(block[i][j]))
		}
	}
	return block
}

func inverseSubBytes(block [][]byte) [][]byte {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			block[i][j] = inv_sbox(int(block[i][j]))
		}
	}
	return block
}

func inverseShiftRows(block [][]byte) [][]byte {
	outputBlock := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		outputBlock[i] = make([]byte, 4)
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			outputBlock[i][j] = block[i][(4+j-i)%4]
		}
	}
	return outputBlock
}

func shiftRows(block [][]byte) [][]byte {
	outputBlock := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		outputBlock[i] = make([]byte, 4)
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			outputBlock[i][j] = block[i][(j+i)%4]
		}
	}
	return outputBlock
}

func inverseMixColumns(block [][]byte) [][]byte {
	outputBlock := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		outputBlock[i] = make([]byte, 4)
	}
	for i := 0; i < 4; i++ {
		outputBlock[0][i] = gmul(14, block[0][i]) ^ gmul(11, block[1][i]) ^ gmul(13, block[2][i]) ^ gmul(9, block[3][i])
		outputBlock[1][i] = gmul(9, block[0][i]) ^ gmul(14, block[1][i]) ^ gmul(11, block[2][i]) ^ gmul(13, block[3][i])
		outputBlock[2][i] = gmul(13, block[0][i]) ^ gmul(9, block[1][i]) ^ gmul(14, block[2][i]) ^ gmul(11, block[3][i])
		outputBlock[3][i] = gmul(11, block[0][i]) ^ gmul(13, block[1][i]) ^ gmul(9, block[2][i]) ^ gmul(14, block[3][i])
	}
	return outputBlock
}

func mixColumns(block [][]byte) [][]byte {
	outputBlock := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		outputBlock[i] = make([]byte, 4)
	}
	for i := 0; i < 4; i++ {
		outputBlock[0][i] = gmul(2, block[0][i]) ^ gmul(3, block[1][i]) ^ block[2][i] ^ block[3][i]
		outputBlock[1][i] = block[0][i] ^ gmul(2, block[1][i]) ^ gmul(3, block[2][i]) ^ block[3][i]
		outputBlock[2][i] = block[0][i] ^ block[1][i] ^ gmul(2, block[2][i]) ^ gmul(3, block[3][i])
		outputBlock[3][i] = gmul(3, block[0][i]) ^ block[1][i] ^ block[2][i] ^ gmul(2, block[3][i])
	}
	return outputBlock
}

func PKCS7(input []byte, l int) []byte {
	padNum := l - len(input)
	for i := 0; i < padNum; i++ {
		input = append(input, byte(padNum))
	}
	return input
}

func CheckPKCS7(input []byte) ([]byte, error) {
	var output []byte
	finalChar := int(input[len(input)-1])
	if finalChar > 16 || finalChar == 0 {
		return nil, errors.New("Invalid PKCS7 padding")
	}

	for i := len(input) - finalChar; i < len(input); i++ {
		if int(input[i]) != finalChar {
			return nil, errors.New("Invalid PKCS7 padding")
		}
	}
	output = input[:len(input)-finalChar]
	return output, nil
}

func EncryptAES(plaintext, key []byte) []byte {
	var ciphertext []byte
	keys := keySchedule(key)
	matrixKeys := make([][][]byte, len(keys))
	for i := 0; i < len(keys); i++ {
		matrixKeys[i] = matrixify(keys[i])
	}

	for i := 0; i < len(plaintext); i += 16 {
		block := plaintext[i:utils.IntMin(i+16, len(plaintext))]
		block = PKCS7(block, 16)
		m := matrixify(block)

		m = applyRoundKey(m, matrixKeys[0])

		for j := 1; j < 10; j++ {
			m = subBytes(m)
			m = shiftRows(m)
			m = mixColumns(m)
			m = applyRoundKey(m, matrixKeys[j])
		}
		m = subBytes(m)
		m = shiftRows(m)
		m = applyRoundKey(m, matrixKeys[10])

		block = blockify(m)
		ciphertext = append(ciphertext, block...)
	}

	return ciphertext
}

func DecryptAES(ciphertext, key []byte) []byte {
	var plaintext []byte
	keys := keySchedule(key)
	reverseKeys := make([][][]byte, len(keys))
	for i := 0; i < len(keys); i++ {
		reverseKeys[i] = matrixify(keys[len(keys)-1-i])
	}

	for i := 0; i < len(ciphertext); i += 16 {
		block := ciphertext[i : i+16]
		m := matrixify(block)

		m = applyRoundKey(m, reverseKeys[0])
		m = inverseShiftRows(m)
		m = inverseSubBytes(m)

		for j := 1; j < 10; j++ {
			m = applyRoundKey(m, reverseKeys[j])
			m = inverseMixColumns(m)
			m = inverseShiftRows(m)
			m = inverseSubBytes(m)
		}
		m = applyRoundKey(m, reverseKeys[10])

		block = blockify(m)
		plaintext = append(plaintext, block...)
	}

	return plaintext
}

func EncryptAESCBC(plaintext, key, iv []byte) []byte {
	var ciphertext []byte
	keys := keySchedule(key)
	matrixKeys := make([][][]byte, len(keys))
	for i := 0; i < len(keys); i++ {
		matrixKeys[i] = matrixify(keys[i])
	}

	for i := 0; i < len(plaintext); i += 16 {
		block := plaintext[i:utils.IntMin(i+16, len(plaintext))]
		block = PKCS7(block, 16)
		block = utils.XOR(block, iv)
		m := matrixify(block)

		m = applyRoundKey(m, matrixKeys[0])

		for j := 1; j < 10; j++ {
			m = subBytes(m)
			m = shiftRows(m)
			m = mixColumns(m)
			m = applyRoundKey(m, matrixKeys[j])
		}
		m = subBytes(m)
		m = shiftRows(m)
		m = applyRoundKey(m, matrixKeys[10])

		block = blockify(m)
		ciphertext = append(ciphertext, block...)
		iv = block
	}

	return ciphertext
}

func DecryptAESCBC(ciphertext, key, iv []byte) []byte {
	var plaintext []byte
	keys := keySchedule(key)
	reverseKeys := make([][][]byte, len(keys))
	for i := 0; i < len(keys); i++ {
		reverseKeys[i] = matrixify(keys[len(keys)-1-i])
	}

	for i := 0; i < len(ciphertext); i += 16 {
		cipherblock := ciphertext[i : i+16]
		m := matrixify(cipherblock)

		m = applyRoundKey(m, reverseKeys[0])
		m = inverseShiftRows(m)
		m = inverseSubBytes(m)

		for j := 1; j < 10; j++ {
			m = applyRoundKey(m, reverseKeys[j])
			m = inverseMixColumns(m)
			m = inverseShiftRows(m)
			m = inverseSubBytes(m)
		}
		m = applyRoundKey(m, reverseKeys[10])

		block := blockify(m)
		block = utils.XOR(block, iv)
		plaintext = append(plaintext, block...)
		iv = cipherblock
	}

	return plaintext
}

func generateKeystream(key []byte, nonce int, length int) []byte {
	keystream := []byte{}
	var counter uint64 = 0

	for len(keystream) < length {
		block := make([]byte, 16)
		binary.LittleEndian.PutUint64(block[:8], uint64(nonce))
		binary.LittleEndian.PutUint64(block[8:], counter)
		keyblock := EncryptAES(block, key)
		keystream = append(keystream, keyblock...)
		counter++
	}
	return keystream[:length]
}

func CTR(plaintext, key []byte, nonce int) []byte {
	keystream := generateKeystream(key, nonce, len(plaintext))
	return utils.XOR(plaintext, keystream)
}

func EditCTR(ciphertext, key []byte, nonce, offset int, plaintext []byte) []byte {
	keystream := generateKeystream(key, nonce, offset+len(plaintext))
	keySlice := keystream[offset:]
	newCiphertext := make([]byte, len(ciphertext))
	copy(newCiphertext[:offset], ciphertext[:offset])
	copy(newCiphertext[offset:offset+len(plaintext)], utils.XOR(plaintext, keySlice))
	copy(newCiphertext[offset+len(plaintext):], ciphertext[offset+len(plaintext):])
	return newCiphertext
}
