# p4ssw0rd

Go password strength validation utilizing the [have i been pwned?](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) API. Make sure you read and abide by their [license](https://haveibeenpwned.com/API/v3#License)

## Usage

```bash
go get github.com/chanced/p4ssw0rd
```

```go
package main

import(
	"context"
	"errors"

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
    _ = eval.Allowed // false because the count of breaches this value has been involved in exceeds BreachLimit
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

## Explanation

The way the package works is the password is hashed (SHA1) then the first 5 characters of that are used to query the API. The result set contains the remainder of the hash, if the password is present, and the count of breaches it has been discovered in. The results look like this:

```
1E2AAA439972480CEC7F16C795BBB429372:1
1E3687A61BFCE35F69B7408158101C8E414:1
1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493
00306FB8A6E528F9B377D068C625E2D5B55:2
00415E48D704BA89B118934A33E202E41F9:1
00DFA98B45FE3EE9D2F7BF6872E37672D03:2
012562CD2D1BECE861B1566A974B52ACBF9:1
012BE47C832BEE70CAA8E89364FF59B09EA:1
0134585DCB1B38E99BD0CDA7E56D42A0C16:1
01D41F17FC9C9CF616DE7A6BA237929AC91:1
01ED16B974AE0010799BF0AE6F77E8F6CC5:10
01FFD148305A472EBCED1BF4E70089A0532:1
```

If you're still concerned about a man in the middle snooping responses, you can turn on buffering which ensures that there are consistently 800 - 1,000 results. See https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding

## Documentation

https://pkg.go.dev/github.com/chanced/p4ssw0rd

## License

p4ssw0rd is licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/chanced/p4ssw0rd/blob/main/LICENSE) for the full license text.
