package oath

import (
	"crypto/cipher"
	"encoding/base32"
)

// Export exports the data from the blob in the OTPAUTH format (first return value),
// as well as the key base32 encoded (second return value)
func Export(blobValue string, c cipher.AEAD, account, issuer string) (string, string, error) {
	data, blb, err := blob(blobValue, c)
	if err != nil {
		return "", "", err
	}

	return blb.OTPURI(account, issuer), base32.StdEncoding.EncodeToString(data.Key), nil
}
