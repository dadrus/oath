package hotp

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/otp/mocks"
)

func TestNew(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc        string
		opts      []Option
		expDigits otp.Digits
	}{
		{uc: "default digits", expDigits: otp.Digits(6)},
		{uc: "set digits", opts: []Option{WithDigits(8)}, expDigits: otp.Digits(8)},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			key := []byte{1, 2, 3}

			// WHEN
			alg := New(key, tc.opts...)

			// THEN
			assert.Equal(t, tc.expDigits, alg.digits)
			assert.Equal(t, key, alg.key)
			assert.NotNil(t, alg.algorithm)
		})
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()

	// test vectors come from RFC 4226 Appendix D

	secret, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	for _, tc := range []struct {
		counter int64
		expOTP  string
	}{
		{counter: 0, expOTP: "755224"},
		{counter: 1, expOTP: "287082"},
		{counter: 2, expOTP: "359152"},
		{counter: 3, expOTP: "969429"},
		{counter: 4, expOTP: "338314"},
		{counter: 5, expOTP: "254676"},
		{counter: 6, expOTP: "287922"},
		{counter: 7, expOTP: "162583"},
		{counter: 8, expOTP: "399871"},
		{counter: 9, expOTP: "520489"},
	} {
		t.Run(fmt.Sprintf("counter %d", tc.counter), func(t *testing.T) {
			// GIVEN
			alg := New(secret)

			// WHEN
			value := alg.Generate(tc.counter)

			// THEN
			assert.Equal(t, tc.expOTP, value)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	// test vectors come from RFC 4226 Appendix D

	secret, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	for _, tc := range []struct {
		counter int64
		otp     string
		success bool
		err     error
	}{
		{counter: 0, otp: "755224", success: true},
		{counter: 1, otp: "287082", success: true},
		{counter: 2, otp: "359152", success: true},
		{counter: 3, otp: "969429", success: true},
		{counter: 4, otp: "338314", success: true},
		{counter: 5, otp: "254676", success: true},
		{counter: 6, otp: "287922", success: true},
		{counter: 7, otp: "162583", success: true},
		{counter: 8, otp: "399871", success: true},
		{counter: 9, otp: "520489", success: true},
		// the following vectors extend those from the rfc also to cover
		// the negative cases
		{counter: 1, otp: " 287082", success: true},
		{counter: 2, otp: "3591521", success: false, err: otp.ErrInvalidLength},
		{counter: 2, otp: "520489", success: false},
	} {
		t.Run(fmt.Sprintf("counter %d, otp %s", tc.counter, tc.otp), func(t *testing.T) {
			// GIVEN
			alg := New(secret)

			// WHEN
			_, err := alg.Validate(tc.otp, tc.counter)

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
		counter   int64
		skew      int
		otp       string
		deviation int64
		success   bool
	}{
		{uc: "success, no deviation", counter: 1, skew: 1, otp: "287082", deviation: 0, success: true},
		{uc: "success, 1 deviation", counter: 0, skew: 1, otp: "287082", deviation: 1, success: true},
		{uc: "success, 2 deviation", counter: 0, skew: 2, otp: "359152", deviation: 2, success: true},
		{uc: "fails, deviates too much", counter: 0, skew: 2, otp: "969429", success: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			alg := New(secret)

			// WHEN
			deviation, err := alg.Validate(tc.otp, tc.counter, WithSkew(tc.skew))

			// THEN
			if tc.success {
				require.NoError(t, err)
				assert.Equal(t, tc.deviation, deviation)
			} else {
				require.ErrorIs(t, err, otp.ErrValidation)
			}
		})
	}
}

func TestAlgorithmExport(t *testing.T) {
	t.Parallel()

	// GIVEN
	secret, err := hex.DecodeString("3132333435363738393031323334353637383930")
	require.NoError(t, err)

	alg := New(secret, WithDigits(otp.Digits(10)))

	exporter := mocks.NewExporterMock(t)
	exporter.EXPECT().SetAlgorithm("hotp")
	exporter.EXPECT().SetHashAlgorithm(otp.SHA1)
	exporter.EXPECT().SetDigits(otp.Digits(10))
	exporter.EXPECT().SetKey(secret)

	// WHEN -> expectations are met
	alg.Export(exporter)
}
