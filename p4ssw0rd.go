// Package p4ssw0rd evaluates password strength utilizing the haveibeenpwned
// database
//
// https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
package p4ssw0rd

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/cenkalti/backoff/v4"
)

// Config parameters when creating a new P4ssw0rd instance
type Config struct {
	// minimum length of a password to be checked.
	//
	// 	default: 6
	MinPasswordLength uint16

	// The max number of times a password is found in data breaches before
	// becoming invalid (or returning an error with Validate)
	//
	// 	default: 10
	BreachLimit uint32

	// Maximum number of attempts to retry reaching haveibeenpwned before
	// returning an error. p4ssw0rd employs exponential backoff.
	//
	// 	default: 3
	MaxPwnedRequestAttempts uint8

	// Each request to the API must be accompanied by a user agent request
	// header. Typically this should be the name of the app consuming the
	// service. A missing user agent will result in an HTTP 403.
	//
	// see https://haveibeenpwned.com/API/v3#UserAgent
	//
	// 	*required

	UserAgent string

	// This is not required, per the HaveIBeenPwned API documentation:
	//
	// "Authorization is required for all APIs that enable searching HIBP by
	// email address, namely retrieving all breaches for an account and
	// retrieving all pastes for an account."
	//
	// Leaving it as a config option for those with keys that would like to
	// future-proof in the event their policy changes.
	//
	//
	// https://haveibeenpwned.com/API/v3#Authorisation
	APIKey string

	// see https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding
	AddPadding bool
}

type P4ssw0rd struct {
	Config
	client *http.Client
}

func New(config Config) (P4ssw0rd, error) {
	if len(config.UserAgent) == 0 {
		return P4ssw0rd{}, ErrMissingUserAgent
	}
	if config.MinPasswordLength == 0 {
		config.MinPasswordLength = 6
	}
	if config.BreachLimit == 0 {
		config.BreachLimit = 10
	}
	if config.MaxPwnedRequestAttempts == 0 {
		config.MaxPwnedRequestAttempts = 3
	}
	return P4ssw0rd{Config: config, client: &http.Client{}}, nil
}

// Validate is like Evaluate but returns an error if the Evaluation fails (too many breaches)
func (p P4ssw0rd) Validate(ctx context.Context, pw string) error {
	eval, err := p.Evaluate(ctx, pw)
	if err != nil {
		return err
	}
	if eval.BreachCount >= p.BreachLimit {
		return newBreachLimitError(eval.BreachCount)
	}
	return nil
}

// Evaluate evaluates a password, checking the haveibeenpwned database for
// breaches. An error is returned if the password length is not long enough
// or errors occurred while querying pwned or hashing the password
func (p P4ssw0rd) Evaluate(ctx context.Context, password string) (Evaluation, error) {
	l := len(password)
	if l < int(p.MinPasswordLength) {
		return Evaluation{Allowed: false}, newMinLengthError(p.MinPasswordLength, uint16(l))
	}
	pwned, err := p.queryPwned(ctx, password)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{BreachCount: pwned, Allowed: pwned < p.BreachLimit}, nil
}

func (p P4ssw0rd) queryPwned(ctx context.Context, v string) (uint32, error) {
	hash := sha1.New()
	bv := []byte(v)
	_, err := hash.Write(bv)
	if err != nil {
		return 0, err
	}
	hp := hex.EncodeToString(hash.Sum(nil))
	hp = strings.ToUpper(hp)
	prefix := hp[:5]
	suffix := hp[5:]
	var res *http.Response
	err = backoff.Retry(func() error {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://api.pwnedpasswords.com/range/"+prefix, nil)
		req.Header.Set("Accept-Encoding", "br")
		req.Header.Set("user-agent", p.UserAgent)
		if len(p.APIKey) > 0 {
			req.Header.Set("hibp-api-key", p.APIKey)
		}
		if err != nil {
			return err
		}
		res, err = p.client.Do(req)
		if err != nil {
			return err
		}
		// https://haveibeenpwned.com/API/v3#ResponseCodes
		switch res.StatusCode {
		case 200:
			return nil
		case 400:
			return errors.New("error: malformed request")
		case 401:
			// this shouldn't happen either
			return backoff.Permanent(errors.New("unauthorized request to haveibeenpwned API: no API key was provided or the key was invalid"))
		case 403:
			return backoff.Permanent(ErrMissingUserAgent)
		case 404:
			// this shouldn't happen per the docs: "There are 1,048,576
			// different hash prefixes between 00000 and FFFFF (16^5) and
			// every single one will return HTTP 200; there is no
			// circumstance in which the API should return HTTP 404."
			return errors.New("error: received a 404 error from haveibeenpwned api")
		case 429:
			// see above... shouldn't happen
			return ErrTooManyRequests
		case 503:
			return ErrServiceUnavailable
		default:
			return fmt.Errorf("http request not successful: received status %d", res.StatusCode)
		}
	}, backoff.WithContext(backoff.WithMaxRetries(backoff.NewExponentialBackOff(), uint64(p.MaxPwnedRequestAttempts)), ctx))

	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return 0, err
	}

	if res == nil || res.Body == nil {
		return 0, errors.New("haveibeenpwned response body was empty")
	}
	br := brotli.NewReader(res.Body)
	s := bufio.NewScanner(br)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		t := s.Text()
		if len(t) == 0 {
			return 0, nil
		}
		spl := strings.Split(t, ":")
		if len(spl) != 2 {
			continue
		}
		fmt.Println(t)

		if spl[0] == suffix {
			r, err := strconv.ParseUint(spl[1], 10, 32)
			if err != nil {
				return 0, err
			}
			return uint32(r), nil
		}
	}
	return 0, nil
}
