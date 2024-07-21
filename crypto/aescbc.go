package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"github.com/alexliesenfeld/eenv/pad/pkcs7"
)

func Encrypt(text string, secretKey []byte, ivString string) (encrypt string, err error) {
	key := secretKey
	iv := make([]byte, 16)
	copy(iv, ivString)

	if _, err = sha256.New().Write(key); err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	plaintext := pkcs7.Pad([]byte(text), block.BlockSize())

	encrypted := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, plaintext)

	encrypt = base64.StdEncoding.EncodeToString(encrypted)

	return
}

func Decrypt(encryptedText string, secretKey []byte, ivString string) ([]byte, error) {
	key := secretKey
	iv := make([]byte, 16)
	copy(iv, ivString)

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	result, err := pkcs7.UnPad(decrypted, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return result, nil
}
