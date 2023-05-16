package oath

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dadrus/oath/otp"
)

var ErrInvalidBlob = errors.New("invalid blob")

type config struct {
	Key           []byte            `json:"key"`
	HashAlgorithm otp.HashAlgorithm `json:"algorithm,omitempty"`
	Type          string            `json:"type"`
	Period        time.Duration     `json:"period,omitempty"`
	Counter       int64             `json:"counter,omitempty"`
	Digits        otp.Digits        `json:"digits,omitempty"`
	T0            int64             `json:"t0,omitempty"`
	Deviation     int64             `json:"deviation,omitempty"`
	Synchronized  bool              `json:"synchronized,omitempty"`
	WorkSkew      int               `json:"skew,omitempty"`
	InitialSkew   int               `json:"initial_skew,omitempty"`
	LastVerified  []string          `json:"last_verified,omitempty"`
}

func (b *config) Skew() int {
	if b.Synchronized {
		return b.WorkSkew
	}

	return b.InitialSkew
}

func (b *config) unmarshal(value string, c cipher.AEAD) error {
	parts := strings.Split(value, "$")
	if len(parts) != 3 {
		return ErrInvalidBlob
	}

	nonce, _ := base64.RawStdEncoding.DecodeString(parts[1])
	encrypted, _ := base64.RawStdEncoding.DecodeString(parts[2])

	unsealed, err := c.Open([]byte{}, nonce, encrypted, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(unsealed, b)
}

func (b *config) marshal(c cipher.AEAD) (string, error) {
	res, err := json.Marshal(b)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, c.NonceSize())
	rand.Read(nonce)

	sealed := c.Seal([]byte{}, nonce, res, nil)

	return fmt.Sprintf(
		"$%s$%s",
		base64.RawStdEncoding.EncodeToString(nonce),
		base64.RawStdEncoding.EncodeToString(sealed),
	), err
}
