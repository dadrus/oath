package oath

import (
	"bytes"
	"time"

	"github.com/dadrus/oath/otp"
)

type Option func(o *config)

func WithDigits(digits otp.Digits) Option {
	return func(o *config) {
		if digits.Length() != 0 {
			o.Digits = digits
		}
	}
}

func WithHashAlgorithm(algorithm otp.HashAlgorithm) Option {
	return func(o *config) {
		if len(algorithm) != 0 {
			o.HashAlgorithm = algorithm
		}
	}
}

func WithTimeStep(step time.Duration) Option {
	return func(o *config) {
		if step != 0 {
			o.Period = step
		}
	}
}

func WithT0(t0 int64) Option {
	return func(o *config) {
		if t0 != 0 {
			o.T0 = t0
		}
	}
}

func WithCounter(counter int64) Option {
	return func(o *config) {
		o.Counter = counter
	}
}

func WithKey(key []byte) Option {
	return func(o *config) {
		if len(key) != 0 {
			o.Key = bytes.Clone(key)
		}
	}
}

func WithWorkSkew(skew int) Option {
	return func(o *config) {
		o.WorkSkew = skew
	}
}

func WithInitialSkew(skew int) Option {
	return func(o *config) {
		o.InitialSkew = skew
	}
}
