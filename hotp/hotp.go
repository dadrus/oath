// Package hotp implements the HOTP algorithm according to RFC 4226
package hotp

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/stephennancekivell/go-future/future"
	"github.com/stephennancekivell/go-future/tuple"

	"github.com/dadrus/oath/otp"
)

type Algorithm struct {
	key       []byte
	digits    otp.Digits
	algorithm otp.HashAlgorithm
}

func New(key []byte, opts ...Option) *Algorithm {
	const defaultOTPLength = 6

	alg := &Algorithm{
		key:       bytes.Clone(key),
		digits:    otp.Digits(defaultOTPLength),
		algorithm: otp.SHA1,
	}

	for _, opt := range opts {
		opt(alg)
	}

	return alg
}

func (a *Algorithm) Key() []byte { return bytes.Clone(a.key) }

func (a *Algorithm) Digits() otp.Digits { return a.digits }

func (a *Algorithm) HashAlgorithm() otp.HashAlgorithm { return a.algorithm }

func (a *Algorithm) Generate(reference int64) string {
	return Truncate(a.digits, a.calculate(reference))
}

func (a *Algorithm) Validate(value string, reference int64, opts ...otp.ValidationOption) (int64, error) {
	// The validation is done for the entire validity window defined by skew
	// Since the validation of each value in the validity window is independent,
	// these validations are done in parallel.
	var group []future.Future[tuple.T2[int64, error]]

	for it := a.iterator(opts, reference); it.HasNext(); {
		group = append(group, a.validateFuture(value, reference, it.Value()))
	}

	return a.futureGroupResult(group)
}

func (a *Algorithm) calculate(reference int64) []byte {
	const intSize = 8

	mac := hmac.New(a.algorithm.Hash, a.key)

	buf := make([]byte, intSize)
	binary.BigEndian.PutUint64(buf, uint64(reference))

	mac.Write(buf)

	return mac.Sum(nil)
}

func (a *Algorithm) iterator(opts []otp.ValidationOption, reference int64) otp.SkewIterator {
	if len(opts) == 0 {
		return WithSkew(0)(reference)
	}

	return opts[0](reference)
}

func (a *Algorithm) validateFuture(value string, steps int64, tbv int64) future.Future[tuple.T2[int64, error]] {
	return future.New(func() tuple.T2[int64, error] {
		if err := a.validate(value, tbv); err != nil {
			return tuple.New2[int64, error](0, err)
		}

		return tuple.New2[int64, error](tbv-steps, nil)
	})
}

func (a *Algorithm) validate(value string, reference int64) error {
	code := strings.TrimSpace(value)

	if len(code) != a.digits.Length() {
		return fmt.Errorf("%w: %d", otp.ErrInvalidLength, len(code))
	}

	calculated := a.Generate(reference)

	if subtle.ConstantTimeCompare([]byte(code), []byte(calculated)) == 0 {
		return otp.ErrValidation
	}

	return nil
}

func (a *Algorithm) futureGroupResult(group []future.Future[tuple.T2[int64, error]]) (int64, error) {
	// Constant execution time
	var (
		deviation *int64
		err       error
	)

	for _, result := range future.Sequence(group).Get() {
		if rDeviation, rErr := result.Values(); rErr != nil {
			if !errors.Is(rErr, otp.ErrValidation) {
				err = rErr
			}
		} else {
			deviation = &rDeviation
		}
	}

	if err != nil {
		return 0, err
	} else if deviation != nil {
		return *deviation, nil
	}

	return 0, otp.ErrValidation
}

func (a *Algorithm) Export(exporter otp.Exporter) {
	exporter.SetAlgorithm("hotp")
	exporter.SetDigits(a.digits)
	exporter.SetKey(a.key)
	exporter.SetHashAlgorithm(a.algorithm)
}
