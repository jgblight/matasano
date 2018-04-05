package hacks

import (
  "github.com/jgblight/matasano/pkg/utils"
)

func IsECB(ciphertext []byte, blockSize int) bool {
  for i := 0; i < len(ciphertext); i+=blockSize {
    chunkOne := ciphertext[i:i+blockSize]
    for j := 0; j < len(ciphertext); j+= blockSize {
      chunkTwo := ciphertext[j:j+blockSize]
      if i != j && utils.HammingDistance(chunkOne, chunkTwo) == 0 {
        return true
      }
    }
  }
  return false
}
