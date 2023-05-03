package oath

type Blob interface {
	Verify(value string) error
	Synchronized() bool
	OTPURI(account, issuer string) string
}
