package p4ssw0rd_test

import (
	"context"
	"encoding/hex"
	"errors"
	"math/rand"
	"time"

	"testing"

	"github.com/chanced/p4ssw0rd"
	"github.com/stretchr/testify/require"
)

// no need for crypto rand
var random = rand.New(rand.NewSource(time.Now().UnixNano()))

func TestP4ssw0rd(t *testing.T) {
	assert := require.New(t)

	//malformed
	_, err := p4ssw0rd.New(p4ssw0rd.Config{})
	assert.Error(err)
	assert.ErrorIs(err, p4ssw0rd.ErrMissingUserAgent)

	pw, err := p4ssw0rd.New(p4ssw0rd.Config{
		MinPasswordLength:       7,
		BreachLimit:             10,
		UserAgent:               "github.com/chanced/p4ssw0rd",
		MaxPwnedRequestAttempts: 3,
		AddPadding:              true,
	})
	assert.NoError(err)
	ctx := context.Background()
	eval, err := pw.Evaluate(ctx, "password")
	assert.NoError(err)
	assert.Greater(eval.BreachCount, uint32(10000), `Breach count for "password" should be greater than 10,000`)
	assert.False(eval.Allowed)
	d := make([]byte, 36)
	_, err = random.Read(d)
	generated := hex.EncodeToString(d)
	assert.NoError(err)

	eval, err = pw.Evaluate(ctx, generated)
	assert.NoError(err)
	assert.Less(eval.BreachCount, uint32(10), "there should be less than 10 breaches for", generated)
	assert.True(eval.Allowed, true)

	eval, err = pw.Evaluate(ctx, "pass")
	assert.Error(err, "pass should fail because it does not meet the minimum char requirements")

	pw.MinPasswordLength = 3

	eval, err = pw.Evaluate(ctx, "pass")
	assert.NoError(err, "pass should no longer throw an error because the threshold has been lowered")

	err = pw.Validate(ctx, "password")
	assert.Error(err)
	var blErr *p4ssw0rd.BreachLimitError
	assert.ErrorAs(err, &blErr)
	if errors.As(err, &blErr) {
		assert.Greater(blErr.BreachCount, uint32(1000))
	}
	pw.MinPasswordLength = 10

	err = pw.Validate(ctx, "pass")
	var mlerr *p4ssw0rd.MinLengthError
	assert.ErrorAs(err, &mlerr)
	errors.As(err, &mlerr)
	assert.Equal(uint16(4), mlerr.Length)
	assert.Equal(mlerr.MinRequired, uint16(10))
}
