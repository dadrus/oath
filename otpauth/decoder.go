package otpauth

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dadrus/oath/hotp"
	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/totp"
)

var (
	ErrUnsupportedURIScheme     = errors.New("unsupported uri scheme")
	ErrUnsupportedOTPAlgorithm  = errors.New("unsupported otp algorithm")
	ErrInvalidSecretEncoding    = errors.New("invalid secret encoding")
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
	ErrNoCounterPresent         = errors.New("no counter present")
)

type Type string

const (
	TOTP = "totp"
	HOTP = "hotp"
)

type AlgorithmParameters struct {
	key           []byte
	hashAlgorithm string
	otpType       Type
	period        time.Duration
	digits        otp.Digits
	counter       int64
	issuer        string
	accountName   string
}

func FromURI(value string) (*AlgorithmParameters, error) {
	// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	uri, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, ErrUnsupportedURIScheme
	}

	if uri.Scheme != "otpauth" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedURIScheme, uri.Scheme)
	}

	if uri.Host != TOTP && uri.Host != HOTP {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedOTPAlgorithm, uri.Host)
	}

	key, err := extractKey(uri)
	if err != nil {
		return nil, err
	}

	algorithm, err := extractHashAlgorithm(uri)
	if err != nil {
		return nil, err
	}

	var (
		counter int64
		period  time.Duration
	)

	if uri.Host == "hotp" {
		if counter = extractCounter(uri); counter == -1 {
			return nil, ErrNoCounterPresent
		}
	} else {
		period = extractPeriod(uri)
	}

	return &AlgorithmParameters{
		key:           key,
		otpType:       Type(uri.Host),
		issuer:        extractIssuer(uri),
		accountName:   extractAccountName(uri),
		period:        period,
		hashAlgorithm: algorithm,
		counter:       counter,
		digits:        extractDigits(uri),
	}, nil
}

func (d *AlgorithmParameters) Algorithm() otp.Algorithm {
	if d.otpType == "totp" {
		return totp.New(
			d.key,
			totp.WithDigits(d.digits),
			totp.WithTimeStep(d.period),
			totp.WithHashAlgorithm(otp.HashAlgorithm(d.hashAlgorithm)),
			totp.WithT0(0),
		)
	}

	return hotp.New(d.key, hotp.WithDigits(d.digits))
}

func (d *AlgorithmParameters) Key() []byte { return bytes.Clone(d.key) }

func (d *AlgorithmParameters) Issuer() string { return d.issuer }

func (d *AlgorithmParameters) AccountName() string { return d.accountName }

func (d *AlgorithmParameters) Counter() int64 { return d.counter }

func (d *AlgorithmParameters) Type() Type { return d.otpType }

func extractKey(uri *url.URL) ([]byte, error) {
	secret := uri.Query().Get("secret")

	// some vendors do not pad the keys
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret += strings.Repeat("=", 8-n)
	}

	// even base32 encoding expects the letters to be in uppercase,
	// some vendors (e.g. Goolge) provide the key in lowercase
	secret = strings.ToUpper(secret)

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, ErrInvalidSecretEncoding
	}

	return key, nil
}

func extractIssuer(uri *url.URL) string {
	// check if the issuer is present in the parameters part
	if issuer := uri.Query().Get("issuer"); len(issuer) != 0 {
		return issuer
	}

	// check if it is in the label part
	path := strings.TrimPrefix(uri.Path, "/")

	i := strings.Index(path, ":")
	if i == -1 {
		return ""
	}

	return path[:i]
}

func extractAccountName(uri *url.URL) string {
	label := strings.TrimPrefix(uri.Path, "/")

	i := strings.Index(label, ":")
	if i == -1 {
		return label
	}

	return label[i+1:]
}

func extractPeriod(uri *url.URL) time.Duration {
	// rfc6238 defines 30 seconds as default
	period := int64(30) //nolint:gomnd

	if u, err := strconv.ParseInt(uri.Query().Get("period"), 10, 64); err == nil {
		period = u
	}

	return time.Duration(period) * time.Second
}

func extractHashAlgorithm(uri *url.URL) (string, error) {
	algorithm := strings.ToUpper(uri.Query().Get("algorithm"))
	switch algorithm {
	case "SHA1", "SHA256", "SHA512":
		return algorithm, nil
	case "":
		return "SHA1", nil
	default:
		return "", ErrUnsupportedHashAlgorithm
	}
}

func extractDigits(uri *url.URL) otp.Digits {
	if value, err := strconv.ParseUint(uri.Query().Get("digits"), 10, 64); err == nil {
		return otp.Digits(value)
	}

	return otp.Digits(6)
}

func extractCounter(uri *url.URL) int64 {
	if value, err := strconv.ParseInt(uri.Query().Get("counter"), 10, 64); err == nil {
		return value
	}

	return -1
}
