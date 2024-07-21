package eenv

import (
	"encoding/hex"
	"github.com/alexliesenfeld/eenv/crypto"
	"github.com/alexliesenfeld/eenv/regex"
	"log/slog"
	"os"
)

// Set this at built time: go build -ldflags "-X 'github.com/alexliesenfeld/eenv.Secret=your_secret_value'"
var secretKey string
var decodedKey []byte

func init() {
	if secretKey == "" {
		secretKey = os.Getenv("ENV_VAR_DECRYPTION_KEY")
	}

	var err error
	decodedKey, err = hex.DecodeString(secretKey)
	if err != nil {
		slog.Error("decoding of secret key was not successful")
	}
}

type Value string

func (s *Value) Decode(cfgValue string) error {
	if !regex.RegexEncryptedValue.MatchString(cfgValue) {
		*s = Value(cfgValue)
		return nil
	}

	encrypted := regex.ExtractEncryptedValue(cfgValue)

	decrypted, err := crypto.Decrypt(encrypted, decodedKey, "")
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
