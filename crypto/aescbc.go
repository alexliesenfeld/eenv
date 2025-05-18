package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/alexliesenfeld/eenv/pad/pkcs7"
	"io"
)

func Encrypt(text string, secretKey []byte) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	plaintext := pkcs7.Pad([]byte(text), block.BlockSize())

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	encrypted := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, plaintext)

	// Prepend IV to ciphertext
	final := append(iv, encrypted...)
	return base64.StdEncoding.EncodeToString(final), nil
}

func Decrypt(encryptedText string, secretKey []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	return pkcs7.UnPad(decrypted, aes.BlockSize)
}
