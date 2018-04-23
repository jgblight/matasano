package hacks

import (
  "time"
  "github.com/jgblight/matasano/pkg/utils"
  "github.com/jgblight/matasano/pkg/rng"
)

const (
  a uint32 = 2567483615
  b uint32 = 2636928640
  c uint32 = 4022730752
  u_mask uint32 = 2147483648
  l_mask uint32 = 2147483647
  u = 11
  s = 7
  t = 15
  l = 18
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

func UndoRightShift(y, shift uint32) uint32 {
  x := (y & utils.CreateMask(0, shift))
  for i := shift; i < 32; i += shift {
    xShifted := x >> shift
    mask := utils.CreateMask(i, i+shift)
    x = (x & utils.CreateMask(0, i)) | ((y ^ xShifted) & mask)
  }
  return x
}

func UndoLeftShift(y, shift, con uint32) uint32 {
  x := (y & utils.CreateMask(32-shift, 32))
  for i := 32 - shift; i >= 0 && i < 32; i -= shift {
    xShifted := (x << shift) & con
    maskStart := uint32(0)
    if shift < i {
        maskStart = i - shift
    }
    mask := utils.CreateMask(maskStart, i)
    x = (x & utils.CreateMask(i, 32)) | ((y ^ xShifted) & mask)
  }
  return x
}

func Untemper(z uint32) uint32 {
  y := UndoRightShift(z, l)
  y = UndoLeftShift(y, t, c)
  y = UndoLeftShift(y, s, b)
  return UndoRightShift(y, u)
}

func GetRandomNumbersFromKeystream(keystream []byte) []uint32 {
  knownNumbers := make([]uint32, len(keystream)/4)
  for i := 0; i < len(knownNumbers); i++ {
    n := uint32(0)
    for j := 0; j < 4; j++ {
      n = n + (uint32(keystream[i*4+j]) << uint32((3-j)*8))
    }
    knownNumbers[i] = n
  }
  return knownNumbers
}

func IsTokenMT19337Stream(token []byte) bool {
  end := time.Now().Unix()
  start := end - 10
  knownNumbers := GetRandomNumbersFromKeystream(token)
  for i := start; i <=end; i++ {
    testMT := rng.New(uint32(i))
    pass := true
    for _, n := range knownNumbers {
      if n != testMT.Next() {
        pass = false
        break
      }
    }
    if pass {
      return true
    }
  }
  return false
}
