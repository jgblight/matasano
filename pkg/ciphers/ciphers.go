package ciphers

import (
  "github.com/jgblight/matasano/pkg/utils"
  "github.com/jgblight/matasano/pkg/rng"
)

func DecryptSingleByteXOR(input []byte) ([]byte, byte, float64) {
  length := len(input)
  bestScore := 100.*float64(length)
  var bestResult []byte
  var bestKey byte
  for i := 0; i < 256; i++ {
    repeat := utils.MakeRepeatChar(byte(i), length)
    candidate := utils.XOR(input, repeat)
    score := utils.CharacterScore(candidate)
    if score < bestScore {
      bestResult = candidate
      bestScore = score
      bestKey = byte(i)
    }
  }
  return bestResult, bestKey, bestScore
}

func RepeatingKeyXOR(plaintext []byte, key []byte) []byte {
  repeatKey := utils.MakeRepeatKey([]byte(key), len(plaintext))
  return utils.XOR(plaintext, repeatKey)
}


func BreakRepeatingKeyXOR(ciphertext []byte) ([]byte, []byte) {
  keySizeGuess := 0
  editDistanceGuess := 100000.
  for i := 2; i <= 40; i++ {
    editDistance := 0
    for j := 0; j < 10; j++ {
      chunkOne := ciphertext[i*j:i*(j+1)]
      chunkTwo := ciphertext[i*(j+1):i*(j+2)]
      editDistance += utils.HammingDistance(chunkOne, chunkTwo)
    }
    editDistanceAvg := float64(editDistance) / float64(i)
    if editDistanceAvg < editDistanceGuess {
      keySizeGuess = i
      editDistanceGuess = editDistanceAvg
    }
  }

  key := make([]byte, keySizeGuess, keySizeGuess)
  for i := 0; i < keySizeGuess; i++ {
    var transposedBlock []byte
    for j := i; j < len(ciphertext); j += keySizeGuess {
      transposedBlock = append(transposedBlock, ciphertext[j])
    }
    _, char, _ := DecryptSingleByteXOR(transposedBlock)
    key[i] = char
  }

  return RepeatingKeyXOR(ciphertext, key), key
}

func MT19937CTR(text []byte, seed int) []byte {
  mt := rng.New(uint32(seed))
  keystream := mt.Stream(len(text))
  return utils.XOR(text, keystream)
}
