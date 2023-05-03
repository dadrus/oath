package oath

import (
	"crypto/cipher"
	"errors"
)

var ErrInvalidOTPType = errors.New("invalid otp type")

// Verify verifies the given otp value (otpValue). While doing so, it unseals the blob with
// algorithm configuration (blobValue) by making use of the provided cipher.
// This function returns the updated sealed blob (first return value), as well as the information
// whether the synchronization with the client application has taken place (second return value).
func Verify(otpValue string, blobValue string, cipher cipher.AEAD) (string, bool, error) {
	data, blb, err := blob(blobValue, cipher)
	if err != nil {
		return "", false, err
	}

	err = blb.Verify(otpValue)
	if err != nil {
		return "", data.Synchronized, err
	}

	raw, err := data.marshal(cipher)

	return raw, data.Synchronized, err
}

func blob(blobValue string, cipher cipher.AEAD) (*config, Blob, error) {
	var data config

	err := data.unmarshal(blobValue, cipher)
	if err != nil {
		return nil, nil, err
	}

	var blb Blob

	switch data.Type {
	case "hotp":
		blb = &hotpBlob{&data}
	case "totp":
		blb = &totpBlob{&data}
	default:
		return nil, nil, ErrInvalidOTPType
	}

	return &data, blb, nil
}
