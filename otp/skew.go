package otp

type SkewIterator interface {
	HasNext() bool
	Value() int64
}

type skew struct {
	current int64
	end     int64
}

func NewSkewIterator(start, end int64) SkewIterator { return &skew{current: start, end: end} }

func (s *skew) HasNext() bool { return s.current != s.end }

func (s *skew) Value() int64 {
	value := s.current

	s.current++

	return value
}
