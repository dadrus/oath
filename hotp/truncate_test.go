package hotp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/oath/otp"
)

func TestTruncate(t *testing.T) {
	t.Parallel()

	// test vectors come from RFC 4226 Appendix D

	for _, tc := range []struct {
		vector string
		result string
	}{
		{vector: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", result: "755224"},
		{vector: "75a48a19d4cbe100644e8ac1397eea747a2d33ab", result: "287082"},
		{vector: "0bacb7fa082fef30782211938bc1c5e70416ff44", result: "359152"},
		{vector: "66c28227d03a2d5529262ff016a1e6ef76557ece", result: "969429"},
		{vector: "a904c900a64b35909874b33e61c5938a8e15ed1c", result: "338314"},
		{vector: "a37e783d7b7233c083d4f62926c7a25f238d0316", result: "254676"},
		{vector: "bc9cd28561042c83f219324d3c607256c03272ae", result: "287922"},
		{vector: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", result: "162583"},
		{vector: "1b3c89f65e6c9e883012052823443f048b4332db", result: "399871"},
		{vector: "1637409809a679dc698207310c8c7fc07290d9e5", result: "520489"},
	} {
		t.Run(tc.vector, func(t *testing.T) {
			// GIVEN
			raw, err := hex.DecodeString(tc.vector)
			require.NoError(t, err)

			// WHEN
			result := Truncate(otp.Digits(6), raw)

			// THEN
			assert.Equal(t, tc.result, result)
		})
	}
}
