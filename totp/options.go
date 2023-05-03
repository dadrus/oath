package totp

import (
	"time"

	"github.com/dadrus/oath/hotp"
	"github.com/dadrus/oath/otp"
)

type Option func(alg *Algorithm)

func WithDigits(digits otp.Digits) Option {
	return func(alg *Algorithm) {
		hotp.WithDigits(digits)(&alg.Algorithm)
	}
}

func WithHashAlgorithm(algorithm otp.HashAlgorithm) Option {
	return func(alg *Algorithm) {
		hotp.WithHashAlgorithm(algorithm)(&alg.Algorithm)
	}
}

func WithTimeStep(step time.Duration) Option {
	return func(alg *Algorithm) {
		if step != 0 {
			alg.step = step
		}
	}
}

func WithT0(t0 int64) Option {
	return func(alg *Algorithm) {
		if t0 != 0 {
			alg.t0 = t0
		}
	}
}

func WithSkew(skew int) otp.ValidationOption {
	return func(steps int64) otp.SkewIterator {
		return otp.NewSkewIterator(steps-int64(skew), steps+int64(skew)+1)
	}
}
