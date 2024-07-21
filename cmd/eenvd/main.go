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

	fmt.Print("Value to eenve: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		panic(err.Error())
	}

	text = strings.TrimSpace(text)

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

	encrypted, err := crypto.Decrypt(text, decodedSecretKey, "")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(string(encrypted))
}
