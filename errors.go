package p4ssw0rd

import (
	"errors"
	"fmt"

	"github.com/dustin/go-humanize"
)

var (
	// ErrMinLengthNotSatisfied indicates that a password does not meet the
	// minimum length requirements
	ErrMinLengthNotSatisfied = errors.New("minimum password length not satisfied")
	// ErrBreachLimitExceeded indicates that the password's breach limit has
	// been exceeded
	ErrBreachLimitExceeded = errors.New("password breach limit exceeded")
	// ErrMissingUserAgent is returned when a UserAgent is not specified
	ErrMissingUserAgent = errors.New("UserAgent was not specified")
	// ErrTooManyRequests occurs when have i been pwned returns a 429 this
	// shouldn't happen per the docs: "There are 1,048,576 different hash
	// prefixes between 00000 and FFFFF (16^5) and every single one will return
	// HTTP 200; there is no circumstance in which the API should return HTTP
	// 404."
	ErrTooManyRequests = errors.New("error: too many requests — the rate limit has been exceeded")
	// Service unavailable — usually returned by Cloudflare if the underlying
	// service is not available
	ErrServiceUnavailable = errors.New("error: service unavailable")
)

type baseErr struct {
	Err error
}

func (e *baseErr) Unwrap() error {
	return e.Err
}
func newBreachLimitError(count uint32) *BreachLimitError {
	return &BreachLimitError{
		baseErr:     baseErr{Err: ErrBreachLimitExceeded},
		BreachCount: count,
	}
}

var _ error = (*BreachLimitError)(nil)
var _ error = (*MinLengthError)(nil)

type BreachLimitError struct {
	baseErr
	BreachCount uint32
}

func (e *BreachLimitError) Error() string {
	return "breach count exceeded: found in " + humanize.Comma(int64(e.BreachCount)) + " data breaches"
}

type MinLengthError struct {
	baseErr
	MinRequired uint16
	Length      uint16
}

func newMinLengthError(required, length uint16) *MinLengthError {
	return &MinLengthError{
		baseErr:     baseErr{Err: ErrMinLengthNotSatisfied},
		MinRequired: required,
		Length:      length,
	}
}

func (e *MinLengthError) Error() string {
	return fmt.Sprintf("minimum length %d of not satisfied", e.MinRequired)
}
