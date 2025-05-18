package regex

import "regexp"

var (
	RegexEncryptedValue = regexp.MustCompile(`^ENC\((.*?)+\)`)
	RegexPlainValue     = regexp.MustCompile(`^PLAIN\((.*?)+\)`)
)

func ExtractEncryptedValue(msg string) string {
	return RegexEncryptedValue.ReplaceAllString(msg, "$1")
}
