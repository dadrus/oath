package otp

import "errors"

var (
	ErrInvalidLength = errors.New("invalid length")
	ErrValidation    = errors.New("otp invalid")
)
