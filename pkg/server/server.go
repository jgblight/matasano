package server

import (
	"math/rand"
	"net/http"
	"time"

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
		return c.String(http.StatusOK, "good")
	}

	return c.String(http.StatusInternalServerError, "bad")
}

func checkHMACFast(c echo.Context) error {
	file := c.QueryParam("file")
	signature := c.QueryParam("signature")

	rand.Seed(13)
	key := secrets.RandomKey()
	generatedHMAC := hashes.HMACSHA1(key, []byte(file))

	if insecureCompare([]byte(signature), []byte(generatedHMAC), 1) {
		return c.String(http.StatusOK, "good")
	}

	return c.String(http.StatusInternalServerError, "bad")
}

func StartServer() {
	e := echo.New()
	e.GET("/checkHMACSlow", checkHMACSlow)
	e.GET("/checkHMACFast", checkHMACFast)
	e.Start(":1323")
}
