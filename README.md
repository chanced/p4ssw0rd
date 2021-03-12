# p4ssw0rd

Go password strength validation utilizing the [have i been pwned?](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) API

Make sure you read and abide by their [license](https://haveibeenpwned.com/API/v3#License)

usage:

```go
package main

import(
    "github.com/chanced/pww0rd"

)

func main() {
    ctx := context.Background()
    pw, err := pww0rd.New(pww0rd.Config{
        UserAgent:               "your site",
        MinPasswordLength:       6,    // defaults to 6
        BreachLimit:             10,   // defaults to 10
        MaxPwnedRequestAttempts: 3,    // defaults to 3
        AddPadding:              true, // defaults to false
    })
    if err != nil {
        // only reason this would happen is if you didn't provide a user agent.
        // see https://haveibeenpwned.com/API/v3#UserAgent
        panic(err)
    }

    eval, err := pw.Eval(ctx, "password")
    if err != nil {
        panic("this shouldn't error unless something goes wrong with connecting to haveibeenpwned")
    }
    _ = eval.Allowed // false because the limit exceeds BreachLimit
    _ = eval.BreachCount // 3861493 as of running this
    _ = eval.Notes // ""; it will remain blank for now. Add your own notes in your handler

    eval, err = pw.Evaluate(ctx, "pass")
    if err != nil {
        // err is a pwword.MinLengthError because len("pass") < pw.MinPasswordLength
        var mlerr *pww0rd.MinLengthError
        if errors.As(err, &mlerr) {
            _ = err.MinRequired // 6, as set by pw.MinPasswordLength
            _ = err.Length // 4
        } else {
            panic("connection issues with haveibeenpwned")
        }
    }
    err = pw.Validate(ctx, "password")
    if err != nil {
        var blerr *p4ssw0rd.BreachLimitError
        if errors.As(err, &blerr) {
            _ = blerr.BreachCount
        }
    }
}

```
