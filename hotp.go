package oath

import (
	"golang.org/x/exp/slices"

	"github.com/dadrus/oath/hotp"
	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/otpauth"
)

type hotpBlob struct {
	c *config
}

func (b *hotpBlob) Synchronized() bool { return b.c.Synchronized }

func (b *hotpBlob) OTPURI(account, issuer string) string {
	return otpauth.ToURI(b.algorithm(), account, otpauth.WithIssuer(issuer))
}

func (b *hotpBlob) Verify(value string) error {
	alg := b.algorithm()
	skew := b.c.Skew()

	deviation, err := alg.Validate(value, b.c.Counter, hotp.WithSkew(skew))
	if err != nil {
		return err
	}

	if !slices.Contains(b.c.LastVerified, value) {
		b.c.Synchronized = true
		b.c.Deviation = deviation
		b.c.Counter = b.c.Counter + deviation + 1

		if len(b.c.LastVerified) >= skew {
			b.c.LastVerified = b.c.LastVerified[1:]
		}

		b.c.LastVerified = append(b.c.LastVerified, value)
	} else {
		return otp.ErrValidation
	}

	return nil
}

func (b *hotpBlob) algorithm() *hotp.Algorithm {
	return hotp.New(b.c.Key,
		hotp.WithHashAlgorithm(b.c.HashAlgorithm),
		hotp.WithDigits(b.c.Digits),
	)
}
