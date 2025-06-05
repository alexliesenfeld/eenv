package eenv

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
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

var Debug = false

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

type Var string

func (s *Var) Decode(cfgValue string) error {
	if regex.RegexPlainValue.MatchString(cfgValue) {
		*s = Var(regex.ExtractPlainValue(cfgValue))
		return nil
	}

	if !regex.RegexEncryptedValue.MatchString(cfgValue) {
		if Debug {
			return fmt.Errorf("could not match an encrypted or plain value in the provided value (value SHA1 + Hex: %x, hint: %v)", sha1.Sum([]byte(cfgValue)), cfgValue[0])
		}

		return fmt.Errorf("could not match an encrypted or plain value in the provided value (value SHA1 + Hex: %x)", sha1.Sum([]byte(cfgValue)))
	}

	encrypted := regex.ExtractEncryptedValue(cfgValue)

	decrypted, err := crypto.Decrypt(encrypted, decodedKey)
	if err != nil {
		if Debug {
			return fmt.Errorf("error decoding decrypting value (value SHA1 + Hex: %x, hint: %v)", sha1.Sum([]byte(cfgValue)), cfgValue[0])
		}

		return fmt.Errorf("error decoding decrypting value (value SHA1 + Hex: %x)", sha1.Sum([]byte(cfgValue)))
	}

	*s = Var(decrypted)

	return nil
}

func (s *Var) EnvDecode(cfgValue string) error {
	if err := s.Decode(cfgValue); err != nil {
		// This interface implements github.com/sethvargo/go-envconfig decoding interface.
		// By default, the decoder will print out the plain-text value if we return an error here.
		// Therefore, we panic instead to prevent leaking secrets.
		panic(err.Error())
	}

	return nil
}

func (s *Var) String() string {
	return string(*s)
}

func (s *Var) Int64() int64 {
	v, err := strconv.ParseInt(s.String(), 10, 64)
	if err != nil {
		panic("cannot parse value as integer")
	}

	return v
}

func (s *Var) Bool() bool {
	v, err := strconv.ParseBool(s.String())
	if err != nil {
		panic("cannot parse value as bool")
	}

	return v
}
