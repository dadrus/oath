package otp

type ValidationOption func(current int64) SkewIterator

//go:generate mockery --name Algorithm --structname AlgorithmMock

type Algorithm interface {
	// Generate generates an otp value
	Generate(reference int64) string

	// Validate validates the given otp value for the given reference
	// opts can optionally be used to provide algorithm specific validation options
	Validate(value string, reference int64, opts ...ValidationOption) (int64, error)

	// Export exports the configuration of the algorithm
	Export(exporter Exporter)
}
