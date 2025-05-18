package eenv

import (
	"encoding/hex"
	"github.com/alexliesenfeld/eenv/crypto"
	"github.com/alexliesenfeld/eenv/regex"
	"log/slog"
	"os"
	"strconv"
)

// SecretKey is the secret key. You can set this at built time like this:
// go build -ldflags "-X 'github.com/alexliesenfeld/eenv.SecretKey=your_secret_value'"
// After initialization, this value will be unset.
var SecretKey string
var decodedKey []byte

func init() {
	if SecretKey == "" {
		// For testing purposes only
		SecretKey = os.Getenv("ENV_VAR_DECRYPTION_KEY")
	}

	var secret = SecretKey
	SecretKey = ""

	if err := SetSecretKey(secret); err != nil {
		panic(err.Error())
	} else if len(decodedKey) == 0 {
		slog.Warn("decryption key is empty")
	}
}

// SetSecretKey sets a secret key that is encoded in hex format.
func SetSecretKey(secret string) error {
	var err error
	decodedKey, err = hex.DecodeString(secret)
	if err != nil {
		slog.Error("decoding of secret key was not successful")
	}

	return nil
}

type Value string

func (s *Value) Decode(cfgValue string) error {
	if !regex.RegexEncryptedValue.MatchString(cfgValue) {
		*s = Value(cfgValue)
		return nil
	}

	encrypted := regex.ExtractEncryptedValue(cfgValue)

	decrypted, err := crypto.Decrypt(encrypted, decodedKey)
	if err != nil {
		return err
	}

	*s = Value(decrypted)

	return nil
}

func (s *Value) EnvDecode(cfgValue string) error {
	return s.Decode(cfgValue)
}

func (s *Value) String() string {
	return string(*s)
}

func (s *Value) Int64() int64 {
	v, err := strconv.ParseInt(s.String(), 10, 64)
	if err != nil {
		panic("cannot parse value as integer")
	}

	return v
}

func (s *Value) Bool() bool {
	v, err := strconv.ParseBool(s.String())
	if err != nil {
		panic("cannot parse value as bool")
	}

	return v
}
