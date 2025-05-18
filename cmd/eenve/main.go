package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/alexliesenfeld/eenv/crypto"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Secret Key: ")
	secretKey, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	secretKey = strings.TrimSpace(secretKey)
	decodedSecretKey, err := hex.DecodeString(secretKey)
	if err != nil {
		panic(err)
	}

	fmt.Print("Value to encrypt: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	text = strings.TrimSpace(text)

	// Generate random IV
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	encrypted, err := crypto.Encrypt(text, decodedSecretKey, string(iv))
	if err != nil {
		panic(err)
	}

	// Prepend IV to ciphertext
	result := append(iv, []byte(encrypted)...)
	fmt.Println(hex.EncodeToString(result))
}
