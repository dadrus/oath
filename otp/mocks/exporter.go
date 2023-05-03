// Code generated by mockery v2.23.1. DO NOT EDIT.

package mocks

import (
	otp "github.com/dadrus/oath/otp"
	mock "github.com/stretchr/testify/mock"

	time "time"
)

// ExporterMock is an autogenerated mock type for the Exporter type
type ExporterMock struct {
	mock.Mock
}

type ExporterMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ExporterMock) EXPECT() *ExporterMock_Expecter {
	return &ExporterMock_Expecter{mock: &_m.Mock}
}

// SetAlgorithm provides a mock function with given fields: algorithm
func (_m *ExporterMock) SetAlgorithm(algorithm string) {
	_m.Called(algorithm)
}

// ExporterMock_SetAlgorithm_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetAlgorithm'
type ExporterMock_SetAlgorithm_Call struct {
	*mock.Call
}

// SetAlgorithm is a helper method to define mock.On call
//   - algorithm string
func (_e *ExporterMock_Expecter) SetAlgorithm(algorithm interface{}) *ExporterMock_SetAlgorithm_Call {
	return &ExporterMock_SetAlgorithm_Call{Call: _e.mock.On("SetAlgorithm", algorithm)}
}

func (_c *ExporterMock_SetAlgorithm_Call) Run(run func(algorithm string)) *ExporterMock_SetAlgorithm_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *ExporterMock_SetAlgorithm_Call) Return() *ExporterMock_SetAlgorithm_Call {
	_c.Call.Return()
	return _c
}

func (_c *ExporterMock_SetAlgorithm_Call) RunAndReturn(run func(string)) *ExporterMock_SetAlgorithm_Call {
	_c.Call.Return(run)
	return _c
}

// SetDigits provides a mock function with given fields: digits
func (_m *ExporterMock) SetDigits(digits otp.Digits) {
	_m.Called(digits)
}

// ExporterMock_SetDigits_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetDigits'
type ExporterMock_SetDigits_Call struct {
	*mock.Call
}

// SetDigits is a helper method to define mock.On call
//   - digits otp.Digits
func (_e *ExporterMock_Expecter) SetDigits(digits interface{}) *ExporterMock_SetDigits_Call {
	return &ExporterMock_SetDigits_Call{Call: _e.mock.On("SetDigits", digits)}
}

func (_c *ExporterMock_SetDigits_Call) Run(run func(digits otp.Digits)) *ExporterMock_SetDigits_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(otp.Digits))
	})
	return _c
}

func (_c *ExporterMock_SetDigits_Call) Return() *ExporterMock_SetDigits_Call {
	_c.Call.Return()
	return _c
}

func (_c *ExporterMock_SetDigits_Call) RunAndReturn(run func(otp.Digits)) *ExporterMock_SetDigits_Call {
	_c.Call.Return(run)
	return _c
}

// SetHashAlgorithm provides a mock function with given fields: algorithm
func (_m *ExporterMock) SetHashAlgorithm(algorithm otp.HashAlgorithm) {
	_m.Called(algorithm)
}

// ExporterMock_SetHashAlgorithm_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetHashAlgorithm'
type ExporterMock_SetHashAlgorithm_Call struct {
	*mock.Call
}

// SetHashAlgorithm is a helper method to define mock.On call
//   - algorithm otp.HashAlgorithm
func (_e *ExporterMock_Expecter) SetHashAlgorithm(algorithm interface{}) *ExporterMock_SetHashAlgorithm_Call {
	return &ExporterMock_SetHashAlgorithm_Call{Call: _e.mock.On("SetHashAlgorithm", algorithm)}
}

func (_c *ExporterMock_SetHashAlgorithm_Call) Run(run func(algorithm otp.HashAlgorithm)) *ExporterMock_SetHashAlgorithm_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(otp.HashAlgorithm))
	})
	return _c
}

func (_c *ExporterMock_SetHashAlgorithm_Call) Return() *ExporterMock_SetHashAlgorithm_Call {
	_c.Call.Return()
	return _c
}

func (_c *ExporterMock_SetHashAlgorithm_Call) RunAndReturn(run func(otp.HashAlgorithm)) *ExporterMock_SetHashAlgorithm_Call {
	_c.Call.Return(run)
	return _c
}

// SetKey provides a mock function with given fields: key
func (_m *ExporterMock) SetKey(key []byte) {
	_m.Called(key)
}

// ExporterMock_SetKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetKey'
type ExporterMock_SetKey_Call struct {
	*mock.Call
}

// SetKey is a helper method to define mock.On call
//   - key []byte
func (_e *ExporterMock_Expecter) SetKey(key interface{}) *ExporterMock_SetKey_Call {
	return &ExporterMock_SetKey_Call{Call: _e.mock.On("SetKey", key)}
}

func (_c *ExporterMock_SetKey_Call) Run(run func(key []byte)) *ExporterMock_SetKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *ExporterMock_SetKey_Call) Return() *ExporterMock_SetKey_Call {
	_c.Call.Return()
	return _c
}

func (_c *ExporterMock_SetKey_Call) RunAndReturn(run func([]byte)) *ExporterMock_SetKey_Call {
	_c.Call.Return(run)
	return _c
}

// SetPeriod provides a mock function with given fields: period
func (_m *ExporterMock) SetPeriod(period time.Duration) {
	_m.Called(period)
}

// ExporterMock_SetPeriod_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetPeriod'
type ExporterMock_SetPeriod_Call struct {
	*mock.Call
}

// SetPeriod is a helper method to define mock.On call
//   - period time.Duration
func (_e *ExporterMock_Expecter) SetPeriod(period interface{}) *ExporterMock_SetPeriod_Call {
	return &ExporterMock_SetPeriod_Call{Call: _e.mock.On("SetPeriod", period)}
}

func (_c *ExporterMock_SetPeriod_Call) Run(run func(period time.Duration)) *ExporterMock_SetPeriod_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(time.Duration))
	})
	return _c
}

func (_c *ExporterMock_SetPeriod_Call) Return() *ExporterMock_SetPeriod_Call {
	_c.Call.Return()
	return _c
}

func (_c *ExporterMock_SetPeriod_Call) RunAndReturn(run func(time.Duration)) *ExporterMock_SetPeriod_Call {
	_c.Call.Return(run)
	return _c
}

// SetT0 provides a mock function with given fields: t0
func (_m *ExporterMock) SetT0(t0 int64) {
	_m.Called(t0)
}

// ExporterMock_SetT0_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetT0'
type ExporterMock_SetT0_Call struct {
	*mock.Call
}

// SetT0 is a helper method to define mock.On call
//   - t0 int64
func (_e *ExporterMock_Expecter) SetT0(t0 interface{}) *ExporterMock_SetT0_Call {
	return &ExporterMock_SetT0_Call{Call: _e.mock.On("SetT0", t0)}
}

func (_c *ExporterMock_SetT0_Call) Run(run func(t0 int64)) *ExporterMock_SetT0_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int64))
	})
	return _c
}

func (_c *ExporterMock_SetT0_Call) Return() *ExporterMock_SetT0_Call {
	_c.Call.Return()
	return _c
}

func (_c *ExporterMock_SetT0_Call) RunAndReturn(run func(int64)) *ExporterMock_SetT0_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewExporterMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewExporterMock creates a new instance of ExporterMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewExporterMock(t mockConstructorTestingTNewExporterMock) *ExporterMock {
	mock := &ExporterMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
