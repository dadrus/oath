package oath

import (
	"crypto/cipher"
	"crypto/rand"
)

type OTPType string

const (
	TOTP = OTPType("totp")
	HOTP = OTPType("hotp")
)

func (t OTPType) New(cipher cipher.AEAD, opts ...Option) (string, error) {
	if t != "hotp" && t != "totp" {
		return "", ErrInvalidOTPType
	}

	data := &config{Type: string(t)}

	for _, opt := range opts {
		opt(data)
	}

	if len(data.Key) == 0 {
		key := make([]byte, data.HashAlgorithm.Size())
		rand.Read(key)

		data.Key = key
	}

	return data.marshal(cipher)
}
