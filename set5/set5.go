package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"github.com/fatih/color"
	"github.com/jgblight/matasano/pkg/ciphers"
	"github.com/jgblight/matasano/pkg/diffie"
	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/secrets"
	"github.com/jgblight/matasano/pkg/server"
	"github.com/jgblight/matasano/pkg/utils"
)

func problemOne() error {
	p := utils.GetNISTPrime()
	g := utils.GetBigInt(2)

	A, a, err := diffie.CreateDHPublicKey(p, g)
	if err != nil {
		return err
	}

	B, b, err := diffie.CreateDHPublicKey(p, g)
	if err != nil {
		return err
	}

	sOne := diffie.CreateDHSharedKey(A, b, p)
	sTwo := diffie.CreateDHSharedKey(B, a, p)
	fmt.Printf("A**b: %s\n", sOne)
	fmt.Printf("B**a: %s\n", sTwo)
	return nil
}

func problemTwo() error {
	alice := secrets.NewDHUser("Alice")
	bob := secrets.NewDHUser("Bob")

	p, g, _, err := alice.SendKeyAndParams()
	if err != nil {
		return err
	}
	bob.ReceiveKeyAndParams(p, g, p)

	_, err = bob.SendKey()
	if err != nil {
		return err
	}
	alice.ReceiveKey(p)

	zero := &big.Int{}
	sharedKey, _ := hex.DecodeString(hashes.SHA1(zero.Bytes()))
	key := sharedKey[:16]

	msg, iv := alice.SendMessage()
	plaintext := ciphers.DecryptAESCBC(msg, key, iv)
	fmt.Printf("Intercepted: %q\n", plaintext)
	bob.ReceiveMessage(msg, iv)

	msg, iv = bob.SendMessage()
	plaintext = ciphers.DecryptAESCBC(msg, key, iv)
	fmt.Printf("Intercepted: %q\n", plaintext)
	alice.ReceiveMessage(msg, iv)

	return nil
}

type malG func(*big.Int) *big.Int

type intercept func([]byte, []byte, *big.Int)

func negotiateParams(gFunc malG, mitmFunc intercept) error {
	alice := secrets.NewDHUser("Alice")
	bob := secrets.NewDHUser("Bob")

	p, _ := alice.SendParams()
	g := gFunc(p)
	bob.ReceiveParams(p, g)
	alice.ReceiveParams(p, g)

	A, err := alice.SendKey()
	if err != nil {
		return err
	}
	bob.ReceiveKey(A)

	B, err := bob.SendKey()
	if err != nil {
		return err
	}
	alice.ReceiveKey(B)

	msg, iv := alice.SendMessage()
	mitmFunc(msg, iv, p)
	bob.ReceiveMessage(msg, iv)

	msg, iv = bob.SendMessage()
	mitmFunc(msg, iv, p)
	alice.ReceiveMessage(msg, iv)

	return nil
}

func problemThree() error {
	fmt.Println("Case 1: g = 1, s = 1")

	g := func(p *big.Int) *big.Int {
		one := utils.GetBigInt(1)
		return one
	}

	i := func(msg, iv []byte, p *big.Int) {
		one := utils.GetBigInt(1)
		sharedKey, _ := hex.DecodeString(hashes.SHA1(one.Bytes()))
		key := sharedKey[:16]
		plaintext := ciphers.DecryptAESCBC(msg, key, iv)
		fmt.Printf("Intercepted: %q\n", plaintext)
	}

	err := negotiateParams(g, i)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Case 2: g = p, s = 0")

	g = func(p *big.Int) *big.Int {
		return p
	}

	i = func(msg, iv []byte, p *big.Int) {
		zero := &big.Int{}
		sharedKey, _ := hex.DecodeString(hashes.SHA1(zero.Bytes()))
		key := sharedKey[:16]
		plaintext := ciphers.DecryptAESCBC(msg, key, iv)
		fmt.Printf("Intercepted: %q\n", plaintext)
	}

	err = negotiateParams(g, i)
	if err != nil {
		return err
	}
	fmt.Println()

	fmt.Println("Case 3: g = p-1, s = p-1 | 1")

	g = func(p *big.Int) *big.Int {
		gPrime := &big.Int{}
		one := utils.GetBigInt(1)
		gPrime.Sub(p, one)
		return gPrime
	}

	i = func(msg, iv []byte, p *big.Int) {
		one := utils.GetBigInt(1)
		sharedKey, _ := hex.DecodeString(hashes.SHA1(one.Bytes()))
		keyOne := sharedKey[:16]
		plaintextOne := ciphers.DecryptAESCBC(msg, keyOne, iv)
		scoreOne := utils.CharacterScore(plaintextOne)

		gPrime := &big.Int{}
		gPrime.Sub(p, one)
		sharedKey, _ = hex.DecodeString(hashes.SHA1(gPrime.Bytes()))
		keyTwo := sharedKey[:16]
		plaintextTwo := ciphers.DecryptAESCBC(msg, keyTwo, iv)
		scoreTwo := utils.CharacterScore(plaintextTwo)

		if scoreOne < scoreTwo {
			fmt.Printf("Intercepted: %q\n", plaintextOne)
		} else {
			fmt.Printf("Intercepted: %q\n", plaintextTwo)
		}
	}

	err = negotiateParams(g, i)
	if err != nil {
		return err
	}
	return nil
}

func problemFour() error {
	client := diffie.NewSRPClient("name@email.com", "password")
	err := client.Initialize()
	if err != nil {
		return err
	}
	err = client.EstablishKey()
	if err != nil {
		return err
	}
	success, err := client.VerifyKey()
	fmt.Printf("Key Verified: %v\n", success)
	return nil
}

func maliciousSRPKey(email string, key *big.Int) (bool, error) {
	salt, _, err := diffie.SRPKeyRequest(email, key)
	if err != nil {
		return false, err
	}

	K := sha256.Sum256(new(big.Int).Bytes())
	mac := hmac.New(sha256.New, K[:])
	mac.Write(salt.Bytes())
	return diffie.SRPVerifyKeyRequest(mac.Sum(nil))
}

func problemFive() error {
	client, err := secrets.InitializeSRPWithUnknownPassword()
	if err != nil {
		return err
	}
	email := client.Email
	N := client.N

	zero := new(big.Int)
	success, err := maliciousSRPKey(email, zero)
	if err != nil {
		return err
	}
	fmt.Printf("Zero Key Verified: %v\n", success)

	success, err = maliciousSRPKey(email, N)
	if err != nil {
		return err
	}
	fmt.Printf("   N Key Verified: %v\n", success)

	success, err = maliciousSRPKey(email, new(big.Int).Mul(N, utils.GetBigInt(2)))
	if err != nil {
		return err
	}
	fmt.Printf(" N*2 Key Verified: %v\n", success)

	return nil
}

type MITMServer struct {
	Email string
	A     *big.Int
	Mac   []byte
}

func (m *MITMServer) sendMaliciousParams(email string, A *big.Int) (*big.Int, *big.Int, *big.Int, error) {
	m.Email = email
	m.A = A
	one := utils.GetBigInt(1)
	two := utils.GetBigInt(2)
	// malicious parametes b=1, B=g, u=1, salt=1
	return one, two, one, nil
}

func (m *MITMServer) saveHMAC(mac []byte) (bool, error) {
	m.Mac = mac
	return true, nil
}

func checkPassword(password []byte, A *big.Int, N *big.Int, providedMac []byte) bool {
	two := utils.GetBigInt(2)
	xH := sha256.Sum256(append([]byte{byte(1)}, password...))
	x := new(big.Int).SetBytes(xH[:])
	v := new(big.Int).Exp(two, x, N)

	S := new(big.Int).Mul(A, v)
	S.Mod(S, N)

	K := sha256.Sum256(S.Bytes())
	mac := hmac.New(sha256.New, K[:])
	mac.Write([]byte{byte(1)})
	if string(providedMac) == string(mac.Sum(nil)) {
		return true
	}
	return false
}

// this is not really a Dictionary
func generatePasswords(prefix []byte, n int, abort <-chan int, ps chan []byte) {
	if n == 0 {
		return
	}

	for i := 97; i < 122; i++ {
		newPrefix := append(prefix, byte(i))
		select {
		case ps <- newPrefix:
		case <-abort:
			return
		}
		generatePasswords(newPrefix, n-1, abort, ps)
	}
	return
}

func problemSix() error {
	fmt.Println("Running Simplified SRP")
	client := diffie.NewSRPClient("name@email.com", "password")
	err := client.Initialize()
	if err != nil {
		return err
	}
	err = client.SimpleEstablishKey()
	if err != nil {
		return err
	}
	success, err := client.VerifyKey()
	fmt.Printf("Key Verified: %v\n", success)

	fmt.Println()
	fmt.Println("Obtaining Password")
	client, err = secrets.InitializeSRPWithUnknownPassword()
	if err != nil {
		return err
	}

	mitm := &MITMServer{}
	client.MITMSimpleEstablishKey(mitm.sendMaliciousParams)
	client.MITMVerifyKey(mitm.saveHMAC)

	foundPassword := ""

	utils.PasswordGenerator(func(password string) bool {
		found := checkPassword([]byte(password), mitm.A, client.N, mitm.Mac)
		if found {
			foundPassword = password
			return true
		}
		return false
	})

	if client.CheckPassword(foundPassword) {
		fmt.Printf("Found Password: %q\n", foundPassword)
	} else {
		fmt.Println("Could not find password")
	}

	return nil
}

func problemSeven() error {
	e, d, n, err := ciphers.RSAKeygen()
	if err != nil {
		return err
	}

	plaintext := []byte("The quick brown fox jumped over the lazy dog")
	fmt.Printf(" Original Plaintext: %q\n", plaintext)

	ciphertext := ciphers.RSAEncrypt(plaintext, e, n)
	fmt.Printf("         Ciphertext: %s\n", ciphertext)

	decrypted, err := ciphers.RSADecrypt(ciphertext, d, n)
	if err != nil {
		return err
	}
	fmt.Printf("Decrypted Plaintext: %q\n", decrypted)

	return nil
}

func problemEight() error {
	originalPlaintext := []byte("The quick brown fox jumped over the lazy dog")

	cHex, n0, err := secrets.RSAEncryptKnownPlaintext(originalPlaintext)
	if err != nil {
		return err
	}
	c0, err := utils.HexToBigint(cHex)
	if err != nil {
		return err
	}
  fmt.Printf("Ciphertext 0: %s\n", cHex)

	cHex, n1, err := secrets.RSAEncryptKnownPlaintext(originalPlaintext)
	if err != nil {
		return err
	}
	c1, err := utils.HexToBigint(cHex)
	if err != nil {
		return err
	}
  fmt.Printf("Ciphertext 1: %s\n", cHex)

	cHex, n2, err := secrets.RSAEncryptKnownPlaintext(originalPlaintext)
	if err != nil {
		return err
	}
	c2, err := utils.HexToBigint(cHex)
	if err != nil {
		return err
	}

  fmt.Printf("Ciphertext 2: %s\n", cHex)

	ms0 := new(big.Int).Mul(n1, n2)
	ms1 := new(big.Int).Mul(n0, n2)
	ms2 := new(big.Int).Mul(n1, n0)

	im0, err := ciphers.InvMod(ms0, n0)
	if err != nil {
		return err
	}

	im1, err := ciphers.InvMod(ms1, n1)
	if err != nil {
		return err
	}
	im2, err := ciphers.InvMod(ms2, n2)
	if err != nil {
		return err
	}

  n012 := new(big.Int).Mul(n0, n1)
	n012.Mul(n012, n2)

	crt0 := new(big.Int).Mul(c0, ms0)
	crt0.Mul(crt0, im0)
	crt1 := new(big.Int).Mul(c1, ms1)
	crt1.Mul(crt1, im1)
	crt2 := new(big.Int).Mul(c2, ms2)
	crt2.Mul(crt2, im2)

	crt := new(big.Int).Add(crt0, crt1)
	crt.Add(crt, crt2)
	crt.Mod(crt, n012)

  x := new(big.Int).Sqrt(crt)

	zero := utils.GetBigInt(0)
  three := utils.GetBigInt(3)

	xDif := utils.GetBigInt(3)
	for xDif.Cmp(zero) != 0 {
		num := new(big.Int).Exp(x, three, zero)
		num.Sub(num, crt)

		den := new(big.Int).Mul(x, x)
		den.Mul(den, three)

		xNext := new(big.Int).Div(num, den)
		xNext.Sub(x, xNext)

		xDif.Sub(x, xNext)

		x = xNext
	}

	decrypted := x.Bytes()
	fmt.Printf("Found Plaintext: %q\n", decrypted)
	return nil
}

func main() {
	header := color.New(color.FgCyan, color.Bold)

	header.Println("Problem 1: Implement Diffie-Hellman")
	err := problemOne()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 2: MITM Diffie-Hellman Attack")
	err = problemTwo()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 3: MITM Diffie-Hellman Attack with Malicious g Parameters")
	err = problemThree()
	if err != nil {
		fmt.Println(err)
	}

	go server.StartServer()
	_, _ = http.Get("http://localhost:1323")

	fmt.Println()
	header.Println("Problem 4: Implement SRP")
	err = problemFour()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 5: SRP Zero Key Attack")
	err = problemFive()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 6: Dictionary Attack on Simplified SRP")
	err = problemSix()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 7: Implement RSA")
	err = problemSeven()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()

	header.Println("Problem 8: Implement E=3 RSA Broadcast Attack")
	err = problemEight()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println()
}
