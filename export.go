package oath

import (
	"crypto/cipher"
	"encoding/base32"
	"strings"
)

// Export exports the data from the blob in the OTPAUTH format (first return value),
// as well as the key base32 encoded (second return value)
func Export(blobValue string, c cipher.AEAD, account, issuer string) (string, string, error) {
	data, blb, err := blob(blobValue, c)
	if err != nil {
		return "", "", err
	}

	encoded := base32.StdEncoding.EncodeToString(data.Key)

	return blb.OTPURI(account, issuer), strings.TrimRight(encoded, "="), nil
}
