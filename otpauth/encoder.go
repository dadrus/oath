package otpauth

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dadrus/oath/otp"
)

type exporter struct {
	key           []byte
	hashAlgorithm string
	otpType       string
	issuer        string
	accountName   string
	counter       int64
	period        time.Duration
	digits        otp.Digits
}

type EncoderOption func(enc *exporter)

func WithIssuer(issuer string) EncoderOption {
	return func(enc *exporter) {
		enc.issuer = issuer
	}
}

func WithCounter(counter int64) EncoderOption {
	return func(enc *exporter) {
		enc.counter = counter
	}
}

type Encoder struct {
	exp *exporter
}

func (e *exporter) SetAlgorithm(algorithm string) { e.otpType = algorithm }

func (e *exporter) SetHashAlgorithm(algorithm otp.HashAlgorithm) {
	e.hashAlgorithm = algorithm.String()
}

func (e *exporter) SetKey(key []byte) { e.key = key }

func (e *exporter) SetDigits(digits otp.Digits) { e.digits = digits }

func (e *exporter) SetT0(_ int64) { /* not supported with otpauth format */ }

func (e *exporter) SetPeriod(period time.Duration) { e.period = period }

func NewEncoder(alg otp.Algorithm, accountName string, opts ...EncoderOption) *Encoder {
	exp := &exporter{accountName: accountName}

	for _, opt := range opts {
		opt(exp)
	}

	alg.Export(exp)

	return &Encoder{exp: exp}
}

func (e *Encoder) Encode() string {
	params := parameter{
		"secret":    []string{base32.StdEncoding.EncodeToString(e.exp.key)},
		"algorithm": []string{strings.ToUpper(e.exp.hashAlgorithm)},
		"digits":    []string{e.exp.digits.String()},
	}

	if len(e.exp.issuer) != 0 {
		params["issuer"] = []string{e.exp.issuer}
	}

	if e.exp.otpType == "totp" {
		params["period"] = []string{strconv.FormatInt(int64(e.exp.period.Seconds()), 10)}
	} else {
		params["counter"] = []string{strconv.FormatInt(e.exp.counter, 10)}
	}

	var label string
	if len(e.exp.issuer) == 0 {
		label = e.exp.accountName
	} else {
		label = fmt.Sprintf("/%s:%s", e.exp.issuer, e.exp.accountName)
	}

	uri := &url.URL{
		Scheme:   "otpauth",
		Host:     e.exp.otpType,
		Path:     label,
		RawQuery: params.Encode(),
	}

	return uri.String()
}

func ToURI(algorithm otp.Algorithm, accountName string, opts ...EncoderOption) string {
	return NewEncoder(algorithm, accountName, opts...).Encode()
}
