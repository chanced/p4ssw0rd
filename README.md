# p4ssw0rd

Go password strength validation utilizing the [have i been pwned?](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) API

Make sure you read and abide by their [license](https://haveibeenpwned.com/API/v3#License)

usage:

```bash
go get github.com/chanced/p4ssw0rd
```

```go
package main

import(
    "github.com/chanced/p4ssw0rd"

)

func main() {
    ctx := context.Background()
    pw, err := p4ssw0rd.New(p4ssw0rd.Config{
        UserAgent:               "your site", // required
        MinPasswordLength:       6,           // default: 6
        BreachLimit:             10,          // default: 10
        MaxPwnedRequestAttempts: 3,           // default: 3
        AddPadding:              false,       // default: false
    })
    if err != nil {
        // The only reason this would happen is if you didn't provide a user agent.
        // see https://haveibeenpwned.com/API/v3#UserAgent
        panic(err)
    }

    eval, err := pw.Evaluate(ctx, "password")
    if err != nil {
        // this shouldn't error unless something goes wrong with connecting to haveibeenpwned
        panic(err)
    }
    _ = eval.Allowed // false because the limit exceeds BreachLimit
    _ = eval.BreachCount // 3861493 as of running this
    _ = eval.Notes // ""; it will remain blank for now. Add your own notes in your handler

    eval, err = pw.Evaluate(ctx, "pass")
    if err != nil {
        // err is a p4ssw0rd.MinLengthError because len("pass") < pw.MinPasswordLength
        var mlerr *p4ssw0rd.MinLengthError
        if errors.As(err, &mlerr) {
            _ = err.MinRequired // 6, as set by pw.MinPasswordLength
            _ = err.Length // 4
        } else {
            //connection issues with haveibeenpwned
            panic(err)
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
