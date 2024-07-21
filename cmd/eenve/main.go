package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/alexliesenfeld/eenv/crypto"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Secret Key: ")
	secretKey, err := reader.ReadString('\n')
	if err != nil {
		panic(err.Error())
	}

	secretKey = strings.TrimSpace(secretKey)
	decodedSecretKey, err := hex.DecodeString(secretKey)
	if err != nil {
		panic(err.Error())
	}

	fmt.Print("Value to eenvd: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		panic(err.Error())
	}

	text = strings.TrimSpace(text)

	encrypted, err := crypto.Encrypt(text, decodedSecretKey, "")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(encrypted)
}
