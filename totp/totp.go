// Package totp implements the TOTP algorithm according to RFC 6238
package totp

import (
	"time"

	"github.com/dadrus/oath/hotp"
	"github.com/dadrus/oath/otp"
)

type Algorithm struct {
	hotp.Algorithm

	step time.Duration
	t0   int64
}

func New(key []byte, opts ...Option) *Algorithm {
	alg := &Algorithm{
		Algorithm: *hotp.New(key),
		step:      30 * time.Second, //nolint:gomnd
		t0:        0,
	}

	for _, opt := range opts {
		opt(alg)
	}

	return alg
}

func (a *Algorithm) Step() time.Duration { return a.step }

func (a *Algorithm) T0() int64 { return a.t0 }

func (a *Algorithm) steps(reference int64) int64 { return (reference - a.t0) / int64(a.step.Seconds()) }

func (a *Algorithm) Generate(reference int64) string {
	return a.Algorithm.Generate(a.steps(reference))
}

func (a *Algorithm) Validate(value string, reference int64, opts ...otp.ValidationOption) (int64, error) {
	deviation, err := a.Algorithm.Validate(value, a.steps(reference), opts...)
	if err != nil {
		return 0, err
	}

	return deviation * int64(a.step.Seconds()), nil
}

func (a *Algorithm) Export(exporter otp.Exporter) {
	a.Algorithm.Export(exporter)

	exporter.SetAlgorithm("totp")
	exporter.SetPeriod(a.step)
	exporter.SetT0(a.t0)
}
