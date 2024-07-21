package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	key := make([]byte, 32) // 256 bits for AES-256
	if _, err := rand.Read(key); err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("Key:", hex.EncodeToString(key))
}
