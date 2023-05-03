package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type HashAlgorithm string

const (
	SHA1   = HashAlgorithm("SHA1")
	SHA256 = HashAlgorithm("SHA256")
	SHA512 = HashAlgorithm("SHA512")
)

func (h HashAlgorithm) String() string {
	return string(h)
}

func (h HashAlgorithm) Size() int {
	switch h {
	case SHA1:
		return sha1.Size //nolint:gosec
	case SHA256:
		return sha256.Size
	case SHA512:
		return sha512.Size
	default:
		panic("unsupported hash algorithm")
	}
}

func (h HashAlgorithm) Hash() hash.Hash {
	switch h {
	case SHA1:
		return sha1.New() //nolint:gosec
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	default:
		panic("unsupported hash algorithm")
	}
}
