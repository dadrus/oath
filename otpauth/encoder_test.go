package otpauth

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/otp/mocks"
)

func TestEncoderEncodeWithIssuer(t *testing.T) {
	t.Parallel()

	// GIVEN
	alg := mocks.NewAlgorithmMock(t)
	alg.EXPECT().Export(mock.MatchedBy(func(exp otp.Exporter) bool {
		exp.SetKey([]byte{1, 2, 3})
		exp.SetDigits(otp.Digits(7))
		exp.SetHashAlgorithm(otp.SHA1)
		exp.SetAlgorithm("totp")
		exp.SetPeriod(10 * time.Second)
		exp.SetT0(10)

		return true
	}))

	enc := NewEncoder(alg, "foo@bar.com", WithIssuer("Acme LTD"))

	// WHEN
	result := enc.Encode()

	// THEN
	uri, err := url.Parse(result)
	require.NoError(t, err)

	issuerAndAccountName := strings.Split(strings.TrimPrefix(uri.Path, "/"), ":")

	assert.Equal(t, "otpauth", uri.Scheme)
	assert.Equal(t, "totp", uri.Host)
	assert.Equal(t, "Acme LTD", issuerAndAccountName[0])
	assert.Equal(t, "Acme LTD", uri.Query().Get("issuer"))
	assert.Equal(t, "foo@bar.com", issuerAndAccountName[1])
	assert.Equal(t, otp.SHA1.String(), uri.Query().Get("algorithm"))
	assert.Equal(t, "7", uri.Query().Get("digits"))
	assert.Equal(t, "10", uri.Query().Get("period"))
}

func TestEncoderEncodeWithoutIssuer(t *testing.T) {
	t.Parallel()

	// GIVEN
	alg := mocks.NewAlgorithmMock(t)
	alg.EXPECT().Export(mock.MatchedBy(func(exp otp.Exporter) bool {
		exp.SetKey([]byte{1, 2, 3})
		exp.SetDigits(otp.Digits(7))
		exp.SetHashAlgorithm(otp.SHA256)
		exp.SetAlgorithm("totp")
		exp.SetPeriod(10 * time.Second)
		exp.SetT0(10)

		return true
	}))

	enc := NewEncoder(alg, "foo@bar.com")

	// WHEN
	result := enc.Encode()

	// THEN
	uri, err := url.Parse(result)
	require.NoError(t, err)

	issuerAndAccountName := strings.Split(strings.TrimPrefix(uri.Path, "/"), ":")

	assert.Equal(t, "otpauth", uri.Scheme)
	assert.Equal(t, "totp", uri.Host)
	assert.Empty(t, uri.Query().Get("issuer"))
	assert.Equal(t, "foo@bar.com", issuerAndAccountName[0])
	assert.Equal(t, otp.SHA256.String(), uri.Query().Get("algorithm"))
	assert.Equal(t, "7", uri.Query().Get("digits"))
	assert.Equal(t, "10", uri.Query().Get("period"))
}
