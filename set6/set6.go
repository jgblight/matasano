package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/secrets"
	"github.com/jgblight/matasano/pkg/utils"
)

const (
	dataDir = "/Users/jennifer/go/src/github.com/jgblight/matasano/data/"
)

func problemOne() error {
	server, err := secrets.NewRSAServer(1024)
	if err != nil {
		return err
	}
	message, err := secrets.GetClientMessage(server)
	if err != nil {
		return err
	}
	fmt.Printf("Original Ciphertext: %s\n", message)
	c, err := utils.HexToBigint(message)
	if err != nil {
		return err
	}
	s := utils.GetBigInt(2)
	cPrime := new(big.Int).Exp(s, server.E, server.N)
	cPrime.Mul(cPrime, c)
	cPrime.Mod(cPrime, server.N)

	cHex := hex.EncodeToString(cPrime.Bytes())
	fmt.Printf("Modified Ciphertext: %s\n", cHex)

	plaintext, err := server.DecryptMessage(cHex)
	if err != nil {
		return err
	}

	pPrime := new(big.Int).SetBytes(plaintext)
	p, err := ciphers.InvMod(s, server.N)
	if err != nil {
		return err
	}
	p.Mul(p, pPrime)
	p.Mod(p, server.N)

	fmt.Printf("   Recovered Message: %q\n", p.Bytes())

	return nil
}

func cubeRoot(n *big.Int) *big.Int {
	xN := utils.GetBigInt(1)
	diff := utils.GetBigInt(5)
	approx := utils.GetBigInt(0)
	two := utils.GetBigInt(2)
	three := utils.GetBigInt(3)

	for diff.CmpAbs(approx) == 1 {
		t := new(big.Int)
		t = t.Div(n, t.Mul(xN, xN))
		xN1 := new(big.Int)
		xN1 = xN1.Div(xN1.Add(xN1.Mul(two, xN), t), three)
		diff = diff.Sub(xN, xN1)
		xN = xN1.Set(xN1)
	}
	return xN
}

func problemTwo() error {
	e, d, n, err := ciphers.RSAKeygen(1024)
	if err != nil {
		return err
	}

	plaintext := []byte("hi mom")
	signature, err := ciphers.PKCS15Sign(plaintext, d, n)
	fmt.Printf("Valid Signature: %s\n", signature)
	verified := ciphers.PKCS15Verify(plaintext, signature, e, n)
	fmt.Printf("Verified: %t\n", verified)

	hash, err := hex.DecodeString(hashes.SHA1(plaintext))
	if err != nil {
		return err
	}

	padding := utils.MakeRepeatChar('\xff', 10)
	padded := append([]byte("\x00\x01"), padding...)
	padded = append(padded, '\x00')
	padded = append(padded, hash...)
	padded = append(padded, utils.MakeRepeatChar('\x00', 95)...)

	x := new(big.Int).SetBytes(padded)
	y := cubeRoot(x)
	y = y.Add(y, utils.GetBigInt(1)) // overestimation > underestimation

	forgery := hex.EncodeToString(y.Bytes())
	fmt.Printf("Forged Signature: %s\n", forgery)
	verified = ciphers.PKCS15Verify(plaintext, forgery, e, n)
	fmt.Printf("Verified: %t\n", verified)

	return nil
}

func recoverKey(k, H, r, s, q *big.Int) *big.Int {
	x := new(big.Int)
	r1 := new(big.Int).ModInverse(r, q)
	x = x.Mod(x.Mul(x.Sub(x.Mul(s, k), H), r1), q)
	return x
}

func problemThree() error {
	params, err := ciphers.NewDSAParams()
	if err != nil {
		return err
	}

	x, y, err := ciphers.DSAKeygen(params)
	if err != nil {
		return err
	}
	m := []byte("I'm a string")

	fmt.Printf("DSA string: %q\n", m)
	signature, err := ciphers.DSASign(m, x, params)
	if err != nil {
		return err
	}

	fmt.Printf("DSA signature: r:%v  s:%v \n", signature.R, signature.S)
	verified, err := ciphers.DSAVerify(m, signature, y, params)
	if err != nil {
		return err
	}
	fmt.Printf("Verified: %v\n\n", verified)

	weakR, _ := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	weakS, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)

	message := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
	hash, err := utils.HexToBigint(hashes.SHA1(message))
	if err != nil {
		return err
	}

	k := new(big.Int)
	for i := 1; i <= 65536; i++ {
		k = k.SetInt64(int64(i))
		r := new(big.Int)
		r = r.Mod(r.Exp(params.G, k, params.P), params.Q)
		if r.Cmp(weakR) == 0 {
			break
		}
	}

	privateKey := recoverKey(k, hash, weakR, weakS, params.Q)
	keyHash := hashes.SHA1([]byte(privateKey.Text(16)))
	if keyHash == "0954edd5e0afe5542a4adf012611a91912a3ec16" {
		fmt.Printf("Found key: %v\n", privateKey)
	}
	return nil
}

func problemFour(input string) error {
	rs := []*big.Int{}
	ss := []*big.Int{}
	ms := []*big.Int{}
	msgs := []string{}
	f, err := os.Open(dataDir + input)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		str := scanner.Text()
		subs := strings.SplitN(str, ": ", 2)
		if subs[0] == "m" {
			n, _ := new(big.Int).SetString(strings.TrimSpace(subs[1]), 16)
			ms = append(ms, n)
		} else if subs[0] == "r" {
			n, _ := new(big.Int).SetString(strings.TrimSpace(subs[1]), 10)
			rs = append(rs, n)
		} else if subs[0] == "s" {
			n, _ := new(big.Int).SetString(strings.TrimSpace(subs[1]), 10)
			ss = append(ss, n)
		} else {
			msgs = append(msgs, subs[1])
		}
	}

	params, err := ciphers.NewDSAParams()
	if err != nil {
		return err
	}
	msgCount := len(ms)
	k := new(big.Int)
	found := false

	for i := 0; i < msgCount; i++ {
		for j := i; j < msgCount; j++ {
			if i == j {
				continue
			}

			if rs[i].Cmp(rs[j]) == 0 {
				num := new(big.Int).Sub(ms[i], ms[j])
				den := new(big.Int)
				den = den.ModInverse(den.Sub(ss[i], ss[j]), params.Q)

				k = k.Mod(k.Mul(num, den), params.Q)

				hash, err := utils.HexToBigint(hashes.SHA1([]byte(msgs[i])))
				if err != nil {
					return err
				}

				privateKey := recoverKey(k, hash, rs[i], ss[i], params.Q)
				keyHash := hashes.SHA1([]byte(privateKey.Text(16)))
				if keyHash == "ca8f6f7c66fa362d40760d135b763eb8527d3d52" {
					fmt.Printf("Found key: %v\n", privateKey)
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}

	return nil
}

func problemFive() error {
	hello := []byte("Hello, world")
	goodbye := []byte("Goodbye, world")

	params, err := ciphers.NewDSAParams()
	if err != nil {
		return err
	}
	x, y, err := ciphers.DSAKeygen(params)
	if err != nil {
		return err
	}

	params.G = utils.GetBigInt(0)
	signature, err := ciphers.DSASign(hello, x, params)
	if err != nil {
		return err
	}

	fmt.Println("g = 0")
	fmt.Printf("Signature: r:%v  s:%v \n", signature.R, signature.S)

	verified, err := ciphers.DSAVerify(hello, signature, y, params)
	if err != nil {
		return err
	}
	fmt.Printf("'Hello' verified: %v\n", verified)
	verified, err = ciphers.DSAVerify(goodbye, signature, y, params)
	if err != nil {
		return err
	}
	fmt.Printf("'Goodbye' verified: %v\n\n", verified)

	fmt.Println("g = p + 1")
	params.G = params.G.Add(params.P, utils.GetBigInt(1))

	z := utils.GetBigInt(10)
	r := new(big.Int)
	r = r.Mod(r.Exp(y, z, params.P), params.Q)
	s := new(big.Int)
	s = s.Mod(s.Mul(r, s.ModInverse(z, params.Q)), params.Q)
	badSignature := &ciphers.DSASignature{R: r, S: s}
	fmt.Printf("Signature: r:%v  s:%v \n", badSignature.R, badSignature.S)

	verified, err = ciphers.DSAVerify(hello, badSignature, y, params)
	if err != nil {
		return err
	}
	fmt.Printf("'Hello' verified: %v\n", verified)
	verified, err = ciphers.DSAVerify(goodbye, badSignature, y, params)
	if err != nil {
		return err
	}
	fmt.Printf("'Goodbye' verified: %v\n", verified)
	return nil
}

func printInline(b []byte) {
	for i := 0; i < len(b); i++ {
		if int(b[i]) < 32 {
			b[i] = byte('?')
		}
	}
	b = append(b, utils.MakeRepeatChar(' ', 30)...)
	fmt.Printf("%s\r", b)
}

func rsaMul(c, multiplier *big.Int, server *secrets.RSAServer) string {
	cPrime := new(big.Int)
	cPrime = cPrime.Mod(cPrime.Mul(c, cPrime.Exp(multiplier, server.E, server.N)), server.N)
	return hex.EncodeToString(cPrime.Bytes())
}

func problemSix() error {
	server, err := secrets.NewRSAServer(1024)
	if err != nil {
		return err
	}
	ciphertext, err := secrets.GetClientMessage2(server)
	if err != nil {
		return err
	}
	c, err := utils.HexToBigint(ciphertext)
	if err != nil {
		return err
	}
	bits := server.N.BitLen()
	lowerBound := utils.GetBigInt(0)
	upperBound := new(big.Int).Set(server.N)

	multiplier := utils.GetBigInt(2)
	two := utils.GetBigInt(2)
	printInline(upperBound.Bytes())
	for i := 0; i < bits; i++ {
		even, err := server.CheckIsEven(rsaMul(c, multiplier, server))
		if err != nil {
			return err
		}
		middle := new(big.Int).Add(lowerBound, upperBound)
		middle = middle.Div(middle, two)
		if even {
			upperBound = middle
		} else {
			lowerBound = middle
		}
		time.Sleep(5 * time.Millisecond)
		printInline(upperBound.Bytes())
		multiplier = multiplier.Mul(multiplier, two)
	}
	fmt.Println()
	return nil
}

type Interval struct {
	Lower      *big.Int
	Upper      *big.Int
	B          *big.Int
	TwoB       *big.Int
	ThreeB     *big.Int
	ThreeBSub1 *big.Int
}

func initialInterval(n *big.Int) *Interval {
	two := utils.GetBigInt(2)
	three := utils.GetBigInt(3)
	B := new(big.Int).Exp(two, utils.GetBigInt(n.BitLen()-16), nil)
	TwoB := new(big.Int).Mul(two, B)
	ThreeB := new(big.Int).Mul(three, B)
	ThreeBSub1 := new(big.Int).Sub(ThreeB, utils.GetBigInt(1))
	return &Interval{TwoB, ThreeBSub1, B, TwoB, ThreeB, ThreeBSub1}
}

func searchS(s0, c *big.Int, server *secrets.RSAServer) (*big.Int, error) {
	s1 := new(big.Int).Set(s0)
	one := utils.GetBigInt(1)
	var err error
	valid := false
	for !valid {
		c1 := rsaMul(c, s1, server)
		valid, err = server.PKCS15Valid(c1)
		if err != nil {
			return nil, err
		}
		if valid {
			return s1, nil
		}
		s1 = s1.Add(s1, one)
	}
	return s1, nil
}

func searchRS(s0, c *big.Int, interval *Interval, server *secrets.RSAServer) (*big.Int, *big.Int, error) {
	one := utils.GetBigInt(1)
	r := new(big.Int)
	r = ceilDiv(r.Mul(utils.GetBigInt(2), r.Sub(r.Mul(interval.Upper, s0), interval.TwoB)), server.N)

	s := new(big.Int)
	minS := new(big.Int)
	maxS := new(big.Int)
	var err error
	valid := false
	for r.Cmp(server.N) == -1 {
		rn := new(big.Int).Mul(r, server.N)
		minS = minS.Div(minS.Add(interval.TwoB, rn), interval.Upper)
		maxS = maxS.Div(maxS.Add(interval.ThreeB, rn), interval.Lower)
		for s.Set(minS); s.Cmp(maxS) == -1; s.Add(s, one) {

			c1 := rsaMul(c, s, server)
			valid, err = server.PKCS15Valid(c1)
			if err != nil {
				return nil, nil, err
			}
			if valid {
				return r, s, nil
			}
		}

		r = r.Add(r, one)
	}
	return nil, nil, errors.New("could not find parameters")
}

func nextInterval(interval *Interval, s, r, n *big.Int) *Interval {
	rn := new(big.Int).Mul(r, n)
	a1 := new(big.Int)
	a1 = ceilDiv(a1.Add(interval.TwoB, rn), s)

	b1 := new(big.Int)
	b1 = b1.Div(b1.Add(interval.ThreeBSub1, rn), s)

	var newInt Interval
	newInt = *interval

	if interval.Lower.Cmp(a1) == -1 {
		newInt.Lower = a1
	}

	if interval.Upper.Cmp(b1) == 1 {
		newInt.Upper = b1
	}

	return &newInt
}

func ceilDiv(x, y *big.Int) *big.Int {
	mod := new(big.Int)
	zero := utils.GetBigInt(0)
	z, mod := new(big.Int).DivMod(x, y, mod)
	if mod.Cmp(zero) != 0 {
		z = z.Add(z, utils.GetBigInt(1))
	}
	return z
}

func allIntervals(currentSet []*Interval, s, n *big.Int) []*Interval {
	one := utils.GetBigInt(1)
	newSet := []*Interval{}
	for i := 0; i < len(currentSet); i++ {
		bounds := currentSet[i]
		minBound := new(big.Int)
		minBound = ceilDiv(minBound.Sub(minBound.Mul(bounds.Lower, s), bounds.ThreeBSub1), n)
		maxBound := new(big.Int)
		maxBound = maxBound.Div(maxBound.Sub(maxBound.Mul(bounds.Upper, s), bounds.TwoB), n)
		r := minBound
		for r.Cmp(maxBound) != 1 {
			next := nextInterval(bounds, s, r, n)
			newSet = append(newSet, next)
			r = r.Add(r, one)
		}
	}
	return newSet
}

func printIntervals(set []*Interval) {
	printInline(set[0].Lower.Bytes())
}

func bleichbacherAttack(c *big.Int, server *secrets.RSAServer) ([]byte, error) {
	one := utils.GetBigInt(1)
	bounds := initialInterval(server.N)
	minS := new(big.Int)
	minS = minS.Div(server.N, bounds.ThreeB)

	s, err := searchS(minS, c, server)
	if err != nil {
		return nil, err
	}
	intervalSet := []*Interval{bounds}
	for i := 0; i < 5000; i++ {
		intervalSet = allIntervals(intervalSet, s, server.N)
		for j := 0; j < len(intervalSet); j++ {
			if intervalSet[j].Lower.Cmp(intervalSet[j].Upper) == 0 {
				return intervalSet[j].Lower.Bytes(), nil
			}
		}
		printIntervals(intervalSet)
		if len(intervalSet) > 1 {
			minS = minS.Add(s, one)
			s, err = searchS(minS, c, server)
			if err != nil {
				return nil, err
			}
		} else {
			_, s, err = searchRS(s, c, bounds, server)
			if err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("Found nothing")
}

func removePadding(plaintext []byte) []byte {
	var i int
	for i = 2; i < len(plaintext); i++ {
		if plaintext[i] == '\x00' {
			break
		}
	}
	return plaintext[i+1 : len(plaintext)]
}

func problemSeven() error {
	server, err := secrets.NewRSAServer(256)
	if err != nil {
		return err
	}
	ciphertext, err := secrets.GetClientMessage3(server)
	if err != nil {
		return err
	}
	c, err := utils.HexToBigint(ciphertext)
	if err != nil {
		return err
	}

	fmt.Printf("Original: %v\n", ciphertext)

	solution, err := bleichbacherAttack(c, server)
	if err != nil {
		return err
	}
	fmt.Printf("Found Message: %q               \n", removePadding(solution))

	return nil
}

func problemEight() error {
	server, err := secrets.NewRSAServer(768)
	if err != nil {
		return err
	}
	ciphertext, err := secrets.GetClientMessage4(server)
	if err != nil {
		return err
	}
	c, err := utils.HexToBigint(ciphertext)
	if err != nil {
		return err
	}

	fmt.Printf("Original: %v\n", ciphertext)

	solution, err := bleichbacherAttack(c, server)
	if err != nil {
		return err
	}
	fmt.Printf("Found Message: %q               \n", removePadding(solution))

	return nil
}

func main() {
	header := color.New(color.FgCyan, color.Bold)

	header.Println("Problem 1: Unpadded Message Recovery Oracle")
	err := problemOne()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 2: Bleichenbacher's e=3 RSA Attack")
	err = problemTwo()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 3: DSA key recovery from nonce")
	err = problemThree()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 4: DSA key recovery from repeated nonce")
	err = problemFour("set6challenge44.txt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 5: DSA parameter tampering")
	err = problemFive()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 6: RSA parity oracle")
	err = problemSix()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 7: Bleichenbacher's PKCS 1.5 Padding Oracle (Part 1)")
	err = problemSeven()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 8: Bleichenbacher's PKCS 1.5 Padding Oracle (Part 2)")
	err = problemEight()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()
}
