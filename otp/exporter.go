package otp

import "time"

//go:generate mockery --name Exporter --structname ExporterMock

type Exporter interface {
	SetAlgorithm(algorithm string)
	SetHashAlgorithm(algorithm HashAlgorithm)
	SetKey(key []byte)
	SetDigits(digits Digits)
	SetT0(t0 int64)
	SetPeriod(period time.Duration)
}
