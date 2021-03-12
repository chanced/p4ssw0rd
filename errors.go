package p4ssw0rd

import (
	"fmt"

	"github.com/dustin/go-humanize"
)

type Err struct {
	Err error
}

func (e *Err) Unwrap() error {
	return e.Err
}
func NewBreachLimitError(count uint32) *BreachLimitError {
	return &BreachLimitError{
		Err:         Err{Err: ErrBreachLimitExceeded},
		BreachCount: count,
	}
}

var _ error = (*BreachLimitError)(nil)
var _ error = (*MinLengthError)(nil)

type BreachLimitError struct {
	Err
	BreachCount uint32
}

func (e *BreachLimitError) Error() string {
	return "breach count exceeded: found in " + humanize.Comma(int64(e.BreachCount)) + " data breaches"
}

type MinLengthError struct {
	Err
	MinRequired uint16
	Length      uint16
}

func NewMinLengthError(required, length uint16) *MinLengthError {
	return &MinLengthError{
		Err:         Err{Err: ErrMinLengthNotSatisfied},
		MinRequired: required,
		Length:      length,
	}
}

func (e *MinLengthError) Error() string {
	return fmt.Sprintf("minimum length %d of not satisfied", e.MinRequired)
}
