package otp

import "fmt"

type Digits int

func (d Digits) Format(value int32) string {
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", d), value)
}

func (d Digits) Length() int { return int(d) }

func (d Digits) String() string { return fmt.Sprintf("%d", d) }
