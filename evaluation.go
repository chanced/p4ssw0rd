package p4ssw0rd

// Evaluation is a non-error summary of whether a password would be valid.
type Evaluation struct {
	BreachCount uint32 `json:"breachCount"`
	Notes       string `json:"notes"`
	Allowed     bool   `json:"allowed"`
}
