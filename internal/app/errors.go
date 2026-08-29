// ABOUTME: The validation error the use case returns for a bad Request field.
// ABOUTME: Carries the field name so a front end can attribute it to whatever it calls that input.
package app

// InvalidRequestError reports a Request field that failed validation before any
// scan ran. Field lets a front end name the input in its own vocabulary (the
// CLI names the flag) instead of matching on message text.
type InvalidRequestError struct {
	Field string
	Err   error
}

// Error reports the underlying validation failure.
func (e *InvalidRequestError) Error() string { return e.Err.Error() }

// Unwrap exposes that failure to errors.Is and errors.As.
func (e *InvalidRequestError) Unwrap() error { return e.Err }
