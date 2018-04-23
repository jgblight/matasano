package rng

const (
	n      uint32 = 624
	m      uint32 = 397
	f      uint32 = 1812433253
	a      uint32 = 2567483615
	b      uint32 = 2636928640
	c      uint32 = 4022730752
	u_mask uint32 = 2147483648
	l_mask uint32 = 2147483647
	u             = 11
	s             = 7
	t             = 15
	l             = 18
)

type MersenneTwister struct {
	x []uint32
}

func New(x uint32) *MersenneTwister {
	mt := &MersenneTwister{}
	mt.x = make([]uint32, n)
	mt.x[0] = x
	for i := 1; i < int(n); i++ {
		x = f*(x^(x>>uint32(30))) + uint32(i)
		mt.x[i] = x
	}
	return mt
}

func Clone(xArr []uint32) *MersenneTwister {
	return &MersenneTwister{xArr}
}

func (mt *MersenneTwister) Next() uint32 {
	x := ((u_mask & mt.x[0]) | (l_mask & mt.x[1]))
	x0 := x & 1
	x = x >> 1
	if x0 == 1 {
		x = x ^ a
	}
	x = mt.x[m] ^ x
	mt.x = append(mt.x[1:], x)

	y := x ^ (x >> u)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	return y ^ (y >> l)
}

func (mt *MersenneTwister) Stream(l int) []byte {
	keystream := make([]byte, l)
	for i := 0; i < l; i += 4 {
		num := mt.Next()
		for j := 0; j < 4; j++ {
			b := byte(num >> uint32(8*(3-j)))
			if i+j < l {
				keystream[i+j] = b
			}
		}
	}
	return keystream
}
