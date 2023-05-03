package hotp

import (
	"github.com/dadrus/oath/otp"
)

type Option func(alg *Algorithm)

func WithDigits(digits otp.Digits) Option {
	return func(alg *Algorithm) {
		if digits.Length() != 0 {
			alg.digits = digits
		}
	}
}

func WithHashAlgorithm(algorithm otp.HashAlgorithm) Option {
	return func(alg *Algorithm) {
		if len(algorithm) != 0 {
			alg.algorithm = algorithm
		}
	}
}

func WithSkew(skew int) otp.ValidationOption {
	return func(current int64) otp.SkewIterator { return otp.NewSkewIterator(current, current+int64(skew)+1) }
}
