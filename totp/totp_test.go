package totp

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/oath/hotp"
	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/otp/mocks"
)

func TestNew(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc   string
		opts []Option
		exp  Algorithm
	}{
		{
			uc: "defaults",
			exp: Algorithm{
				Algorithm: *hotp.New([]byte{}, hotp.WithDigits(otp.Digits(6)), hotp.WithHashAlgorithm(otp.SHA1)),
				step:      30 * time.Second,
				t0:        0,
			},
		},
		{
			uc:   "digits = 8",
			opts: []Option{WithDigits(8)},
			exp: Algorithm{
				Algorithm: *hotp.New([]byte{}, hotp.WithDigits(otp.Digits(8)), hotp.WithHashAlgorithm(otp.SHA1)),
				step:      30 * time.Second,
				t0:        0,
			},
		},
		{
			uc:   "hash = sha256",
			opts: []Option{WithHashAlgorithm(otp.SHA256)},
			exp: Algorithm{
				Algorithm: *hotp.New([]byte{}, hotp.WithDigits(otp.Digits(6)), hotp.WithHashAlgorithm(otp.SHA256)),
				step:      30 * time.Second,
				t0:        0,
			},
		},
		{
			uc:   "step = 45s",
			opts: []Option{WithTimeStep(45 * time.Second)},
			exp: Algorithm{
				Algorithm: *hotp.New([]byte{}, hotp.WithDigits(otp.Digits(6)), hotp.WithHashAlgorithm(otp.SHA1)),
				step:      45 * time.Second,
				t0:        0,
			},
		},
		{
			uc:   "t0 = 100",
			opts: []Option{WithT0(100)},
			exp: Algorithm{
				Algorithm: *hotp.New([]byte{}, hotp.WithDigits(otp.Digits(6)), hotp.WithHashAlgorithm(otp.SHA1)),
				step:      30 * time.Second,
				t0:        100,
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVENhotp
			key := []byte{1, 2, 3}

			// WHEN
			alg := New(key, tc.opts...)

			// THEN
			assert.Equal(t, tc.exp.Digits(), alg.Digits())
			assert.Equal(t, tc.exp.HashAlgorithm(), alg.HashAlgorithm())
			assert.Equal(t, tc.exp.Step(), alg.Step())
			assert.Equal(t, tc.exp.T0(), alg.T0())
			assert.Equal(t, key, alg.Key())
		})
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()

	// test vectors come from RFC 6238 Appendix B

	secret20, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	secret32, err := hex.DecodeString("3132333435363738393031323334353637383930" +
		"313233343536373839303132")
	require.NoError(t, err)

	secret64, err := hex.DecodeString("3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"31323334")
	require.NoError(t, err)

	for _, tc := range []struct {
		time     int64
		hashAlgF otp.HashAlgorithm
		secret   []byte
		expOTP   string
	}{
		{time: 59, hashAlgF: otp.SHA1, secret: secret20, expOTP: "94287082"},
		{time: 59, hashAlgF: otp.SHA256, secret: secret32, expOTP: "46119246"},
		{time: 59, hashAlgF: otp.SHA512, secret: secret64, expOTP: "90693936"},
		{time: 1111111109, hashAlgF: otp.SHA1, secret: secret20, expOTP: "07081804"},
		{time: 1111111109, hashAlgF: otp.SHA256, secret: secret32, expOTP: "68084774"},
		{time: 1111111109, hashAlgF: otp.SHA512, secret: secret64, expOTP: "25091201"},
		{time: 1111111111, hashAlgF: otp.SHA1, secret: secret20, expOTP: "14050471"},
		{time: 1111111111, hashAlgF: otp.SHA256, secret: secret32, expOTP: "67062674"},
		{time: 1111111111, hashAlgF: otp.SHA512, secret: secret64, expOTP: "99943326"},
		{time: 1234567890, hashAlgF: otp.SHA1, secret: secret20, expOTP: "89005924"},
		{time: 1234567890, hashAlgF: otp.SHA256, secret: secret32, expOTP: "91819424"},
		{time: 1234567890, hashAlgF: otp.SHA512, secret: secret64, expOTP: "93441116"},
		{time: 2000000000, hashAlgF: otp.SHA1, secret: secret20, expOTP: "69279037"},
		{time: 2000000000, hashAlgF: otp.SHA256, secret: secret32, expOTP: "90698825"},
		{time: 2000000000, hashAlgF: otp.SHA512, secret: secret64, expOTP: "38618901"},
		{time: 20000000000, hashAlgF: otp.SHA1, secret: secret20, expOTP: "65353130"},
		{time: 20000000000, hashAlgF: otp.SHA256, secret: secret32, expOTP: "77737706"},
		{time: 20000000000, hashAlgF: otp.SHA512, secret: secret64, expOTP: "47863826"},
	} {
		t.Run(fmt.Sprintf("otp %s", tc.expOTP), func(t *testing.T) {
			// GIVEN
			alg := New(
				tc.secret,
				WithDigits(8),
				WithHashAlgorithm(tc.hashAlgF),
			)

			// WHEN
			value := alg.Generate(tc.time)

			// THEN
			assert.Equal(t, tc.expOTP, value)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	// test vectors come from RFC 6238 Appendix B

	secret20, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	secret32, err := hex.DecodeString("3132333435363738393031323334353637383930" +
		"313233343536373839303132")
	require.NoError(t, err)

	secret64, err := hex.DecodeString("3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"31323334")
	require.NoError(t, err)

	for _, tc := range []struct {
		time     int64
		hashAlgF otp.HashAlgorithm
		secret   []byte
		otp      string
		success  bool
		err      error
	}{
		{time: 59, hashAlgF: otp.SHA1, secret: secret20, otp: "94287082", success: true},
		{time: 59, hashAlgF: otp.SHA256, secret: secret32, otp: "46119246", success: true},
		{time: 59, hashAlgF: otp.SHA512, secret: secret64, otp: "90693936", success: true},
		{time: 1111111109, hashAlgF: otp.SHA1, secret: secret20, otp: "07081804", success: true},
		{time: 1111111109, hashAlgF: otp.SHA256, secret: secret32, otp: "68084774", success: true},
		{time: 1111111109, hashAlgF: otp.SHA512, secret: secret64, otp: "25091201", success: true},
		{time: 1111111111, hashAlgF: otp.SHA1, secret: secret20, otp: "14050471", success: true},
		{time: 1111111111, hashAlgF: otp.SHA256, secret: secret32, otp: "67062674", success: true},
		{time: 1111111111, hashAlgF: otp.SHA512, secret: secret64, otp: "99943326", success: true},
		{time: 1234567890, hashAlgF: otp.SHA1, secret: secret20, otp: "89005924", success: true},
		{time: 1234567890, hashAlgF: otp.SHA256, secret: secret32, otp: "91819424", success: true},
		{time: 1234567890, hashAlgF: otp.SHA512, secret: secret64, otp: "93441116", success: true},
		{time: 2000000000, hashAlgF: otp.SHA1, secret: secret20, otp: "69279037", success: true},
		{time: 2000000000, hashAlgF: otp.SHA256, secret: secret32, otp: "90698825", success: true},
		{time: 2000000000, hashAlgF: otp.SHA512, secret: secret64, otp: "38618901", success: true},
		{time: 20000000000, hashAlgF: otp.SHA1, secret: secret20, otp: "65353130", success: true},
		{time: 20000000000, hashAlgF: otp.SHA256, secret: secret32, otp: "77737706", success: true},
		{time: 20000000000, hashAlgF: otp.SHA512, secret: secret64, otp: "47863826", success: true},
		// the following vectors extend those from the rfc also to cover
		// the negative cases
		{time: 1234567890, hashAlgF: otp.SHA1, secret: secret20, otp: " 89005924", success: true},
		{time: 1234567890, hashAlgF: otp.SHA1, secret: secret20, otp: "890059245", success: false, err: otp.ErrInvalidLength},
		{time: 1234567890, hashAlgF: otp.SHA1, secret: secret20, otp: "89005925", success: false},
	} {
		t.Run(fmt.Sprintf("otp %s", tc.otp), func(t *testing.T) {
			// GIVEN
			alg := New(
				tc.secret,
				WithDigits(8),
				WithHashAlgorithm(tc.hashAlgF),
			)

			// WHEN
			_, err := alg.Validate(tc.otp, tc.time)

			// THEN
			if tc.success {
				require.NoError(t, err)
			} else {
				if tc.err != nil {
					assert.ErrorIs(t, err, tc.err)
				} else {
					assert.ErrorIs(t, err, otp.ErrValidation)
				}
			}
		})
	}
}

func TestValidateWithSkew(t *testing.T) {
	t.Parallel()

	secret, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	for _, tc := range []struct {
		uc        string
		time      int64
		skew      int
		otp       string
		deviation int64
		success   bool
	}{
		{
			uc:        "success, +30 sec deviation",
			time:      1111111109 - 30,
			skew:      2,
			otp:       "07081804",
			deviation: 30,
			success:   true,
		},
		{
			uc:        "success, +60 sec deviation",
			time:      1111111109 - 60,
			skew:      2,
			otp:       "07081804",
			deviation: 60,
			success:   true,
		},
		{
			uc:      "fails, time deviates to much in the past",
			time:    1111111109 - 90,
			skew:    2,
			otp:     "07081804",
			success: false,
		},
		{
			uc:        "success, no deviation",
			time:      1111111109,
			skew:      2,
			otp:       "07081804",
			deviation: 0,
			success:   true,
		},
		{
			uc:        "success, -30 sec deviation",
			time:      1111111109 + 30,
			skew:      2,
			otp:       "07081804",
			deviation: -30,
			success:   true,
		},
		{
			uc:        "success, -60 sec deviation",
			time:      1111111109 + 60,
			skew:      2,
			otp:       "07081804",
			deviation: -60,
			success:   true,
		},
		{
			uc:      "fails, time deviates to much in the future",
			time:    1111111109 + 90,
			skew:    2,
			otp:     "07081804",
			success: false,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			alg := New(secret, WithDigits(8))

			deviation, err := alg.Validate(tc.otp, tc.time, WithSkew(tc.skew))

			if tc.success {
				require.NoError(t, err)
				assert.Equal(t, tc.deviation, deviation)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, otp.ErrValidation)
			}
		})
	}
}

func TestExport(t *testing.T) {
	t.Parallel()

	// GIVEN
	secret, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	alg := New(secret,
		WithDigits(otp.Digits(8)),
		WithHashAlgorithm(otp.SHA256),
		WithT0(10),
		WithTimeStep(45*time.Second),
	)

	exporter := mocks.NewExporterMock(t)
	exporter.EXPECT().SetAlgorithm("hotp")
	exporter.EXPECT().SetAlgorithm("totp")
	exporter.EXPECT().SetHashAlgorithm(otp.SHA256)
	exporter.EXPECT().SetDigits(otp.Digits(8))
	exporter.EXPECT().SetPeriod(45 * time.Second)
	exporter.EXPECT().SetT0(int64(10))
	exporter.EXPECT().SetKey(secret)

	// WHEN -> expectations are met
	alg.Export(exporter)
}
