package otpauth

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/oath/hotp"
	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/totp"
)

func TestFromURI(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		vector string
		result AlgorithmParameters
		err    error
	}{
		{
			// this vector is taken from https://github.com/google/google-authenticator/wiki/Key-Uri-Format
			vector: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "totp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				period:        30 * time.Second,
				digits:        otp.Digits(6),
			},
		},
		{
			// this vector is as above, but with key lowercase
			vector: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=hxdmvjecjjwsrb3hwizr4ifugftmxboz&" +
				"issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "totp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				period:        30 * time.Second,
				digits:        otp.Digits(6),
			},
		},
		{
			// same as above, but with sha-256 and digits length of 8
			vector: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=SHA256&digits=8&period=30",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA256",
				otpType:       "totp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				period:        30 * time.Second,
				digits:        otp.Digits(8),
			},
		},
		{
			// same as above, but with sha-512 and period 60
			vector: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=SHA512&digits=6&period=60",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA512",
				otpType:       "totp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				period:        60 * time.Second,
				digits:        otp.Digits(6),
			},
		},
		{
			// this vector is as above, but without issuer in the query
			vector: "otpauth://totp/ACME%20Co:john.doe@email.com?secret=hxdmvjecjjwsrb3hwizr4ifugftmxboz&" +
				"algorithm=SHA1&digits=6&period=30",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "totp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				period:        30 * time.Second,
				digits:        otp.Digits(6),
			},
		},
		{
			// this vector is as above, but with issuer present only in the query part
			vector: "otpauth://totp/john.doe@email.com?secret=hxdmvjecjjwsrb3hwizr4ifugftmxboz&" +
				"issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "totp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				period:        30 * time.Second,
				digits:        otp.Digits(6),
			},
		},
		{
			// same as above but for hotp and digits = 8
			vector: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=hxdmvjecjjwsrb3hwizr4ifugftmxboz&" +
				"issuer=ACME%20Co&algorithm=SHA1&digits=8&counter=5",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "hotp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				counter:       5,
				digits:        otp.Digits(8),
			},
		},
		{
			// same as above but hotp and without digits and hotp
			vector: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=SHA1&counter=1",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "hotp",
				issuer:        "ACME Co",
				accountName:   "john.doe@email.com",
				digits:        otp.Digits(6),
				counter:       1,
			},
		},
		{
			// same as above but hotp and without digits and issuer
			vector: "otpauth://hotp/john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA1&counter=10",
			result: AlgorithmParameters{
				key: func() []byte {
					val, _ := hex.DecodeString("3dc6caa4824a6d288767b2331e20b43166cb85d9")

					return val
				}(),
				hashAlgorithm: "SHA1",
				otpType:       "hotp",
				accountName:   "john.doe@email.com",
				digits:        otp.Digits(6),
				counter:       10,
			},
		},
		{
			// missing counter for hotp
			vector: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=hxdmvjecjjwsrb3hwizr4ifuftmxboz&" +
				"issuer=ACME%20Co&algorithm=SHA1&digits=8",
			err: ErrNoCounterPresent,
		},
		{
			// bad encoded key
			vector: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=hxdmvjecjjwsrb3hwizr4ifu§$ftmxboz&" +
				"issuer=ACME%20Co&algorithm=SHA1&digits=8",
			err: ErrInvalidSecretEncoding,
		},
		{
			// unsupported hash algorithm
			vector: "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=md5&digits=8",
			err: ErrUnsupportedHashAlgorithm,
		},
		{
			// unsupported otp algorithm
			vector: "otpauth://otp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=sha1&digits=8",
			err: ErrUnsupportedOTPAlgorithm,
		},
		{
			// unsupported otp algorithm
			vector: "otpauth://otp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=sha1&digits=8",
			err: ErrUnsupportedOTPAlgorithm,
		},
		{
			// invalid scheme
			vector: "foo://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=sha1&digits=8",
			err: ErrUnsupportedURIScheme,
		},
		{
			// malformed uri
			vector: "{otpauth}://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&" +
				"issuer=ACME%20Co&algorithm=sha1&digits=8",
			err: ErrUnsupportedURIScheme,
		},
	} {
		t.Run(tc.vector, func(t *testing.T) {
			// WHEN
			blob, err := FromURI(tc.vector)

			// THEN
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.result, *blob)
			}
		})
	}
}

func TestDecodedOTPAlgorithm(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		vector  string
		otpType otp.Algorithm
	}{
		{
			uc: "totp",
			vector: "otpauth://totp/FooBar:foo@bar.com?algorithm=SHA512&digits=10&" +
				"issuer=FooBar&period=45&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			otpType: &totp.Algorithm{},
		},
		{
			uc:      "hotp",
			vector:  "otpauth://hotp/FooBar:foo@bar.com?issuer=FooBar&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			otpType: &hotp.Algorithm{},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			dec, err := FromURI(tc.vector)
			require.NoError(t, err)

			alg := dec.Algorithm()
			require.NotNil(t, alg)
			assert.IsType(t, tc.otpType, alg)

			value := alg.Generate(time.Now().Unix())

			assert.Len(t, value, dec.digits.Length())
		})
	}
}
