package server

import (
	"crypto/hmac"
	crng "crypto/rand"
	"crypto/sha256"
	"math/big"
	"math/rand"
	"net/http"
	"time"

	"github.com/jgblight/matasano/pkg/diffie"
	"github.com/jgblight/matasano/pkg/hashes"
	"github.com/jgblight/matasano/pkg/secrets"
	"github.com/labstack/echo"
)

func insecureCompare(bufOne, bufTwo []byte, leak int) bool {
	ms, _ := time.ParseDuration("1000000ns")
	sleepDuration := time.Duration(leak) * ms
	if len(bufOne) < len(bufTwo) || len(bufTwo) < len(bufOne) {
		return false
	}
	for i := 0; i < len(bufOne); i++ {
		if bufOne[i] != bufTwo[i] {
			return false
		}
		time.Sleep(sleepDuration)
	}
	return true
}

func checkHMACSlow(c echo.Context) error {
	file := c.QueryParam("file")
	signature := c.QueryParam("signature")

	rand.Seed(12)
	key := secrets.RandomKey()
	generatedHMAC := hashes.HMACSHA1(key, []byte(file))

	if insecureCompare([]byte(signature), []byte(generatedHMAC), 50) {
		return c.String(http.StatusOK, "Ok")
	}

	return c.String(http.StatusInternalServerError, "Nope")
}

func checkHMACFast(c echo.Context) error {
	file := c.QueryParam("file")
	signature := c.QueryParam("signature")

	rand.Seed(13)
	key := secrets.RandomKey()
	generatedHMAC := hashes.HMACSHA1(key, []byte(file))

	if insecureCompare([]byte(signature), []byte(generatedHMAC), 1) {
		return c.String(http.StatusOK, "Ok")
	}

	return c.String(http.StatusInternalServerError, "Nope")
}

type SRPServer struct {
	email    string
	password string
	N        *big.Int
	g        *big.Int
	k        *big.Int
	salt     *big.Int
	v        *big.Int
	K        []byte
}

var activeSession SRPServer

func setParams(c echo.Context) error {
	activeSession = SRPServer{}
	activeSession.email = c.FormValue("email")
	password := c.FormValue("password")

	var ok bool
	activeSession.N, ok = new(big.Int).SetString(c.FormValue("N"), 16)
	if !ok {
		return c.String(http.StatusInternalServerError, "Nope")
	}

	activeSession.g, ok = new(big.Int).SetString(c.FormValue("g"), 10)
	if !ok {
		return c.String(http.StatusInternalServerError, "Nope")
	}

	activeSession.k, ok = new(big.Int).SetString(c.FormValue("k"), 10)
	if !ok {
		return c.String(http.StatusInternalServerError, "Nope")
	}

	salt, err := crng.Int(crng.Reader, new(big.Int).SetInt64(256))
	if err != nil {
		return err
	}
	activeSession.salt = salt

	xH := sha256.Sum256(append(salt.Bytes(), []byte(password)...))
	x := new(big.Int).SetBytes(xH[:])
	activeSession.v = new(big.Int).Exp(activeSession.g, x, activeSession.N)

	return c.String(http.StatusOK, "Ok")
}

type keyResponse struct {
	Salt string `json:"salt"`
	B    string `json:"B"`
	U    string `json:"u"`
}

func establishKey(c echo.Context) error {
	A, ok := new(big.Int).SetString(c.FormValue("A"), 16)
	if !ok {
		return c.String(http.StatusInternalServerError, "Nope")
	}
	B, b, err := diffie.CreateDHPublicKey(activeSession.N, activeSession.g)
	if err != nil {
		return err
	}
	B.Add(B, new(big.Int).Mul(activeSession.k, activeSession.v))

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	A.Mul(A, new(big.Int).Exp(activeSession.v, u, activeSession.N))
	S := new(big.Int).Exp(A, b, activeSession.N)

	K := sha256.Sum256(S.Bytes())
	activeSession.K = K[:]

	resp := keyResponse{
		Salt: activeSession.salt.Text(16),
		B:    B.Text(16),
	}

	return c.JSON(http.StatusOK, resp)
}

func verifyKey(c echo.Context) error {
	sentMac := []byte(c.FormValue("mac"))
	mac := hmac.New(sha256.New, activeSession.K)
	mac.Write(activeSession.salt.Bytes())
	if hmac.Equal(sentMac, mac.Sum(nil)) {
		return c.String(http.StatusOK, "Ok")
	}
	return c.String(http.StatusBadRequest, "Nope")
}

func simpleEstablishKey(c echo.Context) error {
	A, ok := new(big.Int).SetString(c.FormValue("A"), 16)
	if !ok {
		return c.String(http.StatusInternalServerError, "Nope")
	}
	B, b, err := diffie.CreateDHPublicKey(activeSession.N, activeSession.g)
	if err != nil {
		return err
	}

	maxInt, _ := new(big.Int).SetString("340282366920938463463374607431768211455", 10)
	u, err := crng.Int(crng.Reader, maxInt)
	if err != nil {
		return err
	}

	A.Mul(A, new(big.Int).Exp(activeSession.v, u, activeSession.N))
	S := new(big.Int).Exp(A, b, activeSession.N)

	K := sha256.Sum256(S.Bytes())
	activeSession.K = K[:]

	resp := keyResponse{
		Salt: activeSession.salt.Text(16),
		B:    B.Text(16),
		U:    u.Text(16),
	}

	return c.JSON(http.StatusOK, resp)
}

func StartServer() {
	e := echo.New()
	e.GET("/checkHMACSlow", checkHMACSlow)
	e.GET("/checkHMACFast", checkHMACFast)
	e.POST("/setSRPParams", setParams)
	e.POST("/establishKey", establishKey)
	e.POST("/simpleEstablishKey", simpleEstablishKey)
	e.POST("/verifyKey", verifyKey)
	e.Start(":1323")
}
