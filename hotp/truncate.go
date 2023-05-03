package hotp

import (
	"math"

	"github.com/dadrus/oath/otp"
)

// Truncate implements the "dynamic truncation" as defined in RFC 4226
// See http://tools.ietf.org/html/rfc4226#section-5.4 for details
func Truncate(digits otp.Digits, sum []byte) string {
	//nolint:gomnd
	offset := sum[len(sum)-1] & 0xf
	//nolint:gomnd
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	otp := int32(value % int64(math.Pow10(digits.Length())))

	return digits.Format(otp)
}
