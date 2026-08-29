// ABOUTME: The validation error the use case returns for a bad Request field.
// ABOUTME: Carries the field name so a front end can attribute it to whatever it calls that input.
package app

// InvalidRequestError reports a Request field that failed validation before
// any scan ran. Field is the Request field name; a front end maps it to its
// own vocabulary (the CLI names the flag the value arrived on) rather than
// matching on the message text.
type InvalidRequestError struct {
	Field string
	Err   error
}

func (e *InvalidRequestError) Error() string { return e.Err.Error() }

func (e *InvalidRequestError) Unwrap() error { return e.Err }
