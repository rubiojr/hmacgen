package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

func errExit(msg string, code int) {
	_, err := fmt.Fprintln(os.Stderr, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
	}
	os.Exit(code)
}

func signMessage(key string, ts time.Time) (string, error) {
	mac := hmac.New(sha256.New, []byte(key))
	buf := make([]byte, 0, mac.Size())
	buf = strconv.AppendInt(buf, ts.Unix(), 10)

	mac.Write(buf)
	sum := mac.Sum(buf[:0])

	return fmt.Sprintf("%d.%s", ts.Unix(), hex.EncodeToString(sum)), nil
}

func main() {
	hmacKey := os.Getenv("HMAC_KEY")
	if hmacKey == "" {
		errExit("usage: HMAC_KEY=\"<hex key1>,<hex key2>...\" hmacgen", 2)
	}

	header, err := signMessage(hmacKey, time.Now())
	if err != nil {
		errExit("error generating the HMAC", 1)
	}

	fmt.Println(header)
}
