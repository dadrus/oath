package oath

import (
	"time"

	"golang.org/x/exp/slices"

	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/otpauth"
	"github.com/dadrus/oath/totp"
)

type totpBlob struct {
	c *config
}

func (b *totpBlob) Synchronized() bool { return b.c.Synchronized }

func (b *totpBlob) OTPURI(account, issuer string) string {
	return otpauth.ToURI(b.algorithm(), account, otpauth.WithIssuer(issuer))
}

func (b *totpBlob) Verify(value string) error {
	alg := b.algorithm()

	deviation, err := alg.Validate(value, time.Now().Unix()+b.c.Deviation, totp.WithSkew(b.c.Skew))
	if err != nil {
		return err
	}

	if !slices.Contains(b.c.LastVerified, value) {
		b.c.Deviation = deviation
		b.c.Synchronized = true

		if len(b.c.LastVerified) >= b.c.Skew*2+1 {
			b.c.LastVerified = b.c.LastVerified[1:]
		}

		b.c.LastVerified = append(b.c.LastVerified, value)
	} else {
		return otp.ErrValidation
	}

	return nil
}

func (b *totpBlob) algorithm() *totp.Algorithm {
	return totp.New(b.c.Key,
		totp.WithHashAlgorithm(b.c.HashAlgorithm),
		totp.WithDigits(b.c.Digits),
		totp.WithTimeStep(b.c.Period),
		totp.WithT0(b.c.T0),
	)
}
