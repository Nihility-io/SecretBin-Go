package secretbin

import (
	"fmt"
)

var (
	// List of possible errors returned by the SecretBin API.
	ErrInvalidExpirationTime = &SecretBinError{Name: "InvalidExpirationTime"}
	ErrSecretNotFound        = &SecretBinError{Name: "SecretNotFoundError"}
	ErrSecretAlreadyExists   = &SecretBinError{Name: "SecretAlreadyExistsError"}
	ErrSecretList            = &SecretBinError{Name: "SecretListError"}
	ErrSecretRead            = &SecretBinError{Name: "SecretReadError"}
	ErrSecretCreate          = &SecretBinError{Name: "SecretCreateError"}
	ErrSecretUpdate          = &SecretBinError{Name: "SecretUpdateError"}
	ErrSecretDelete          = &SecretBinError{Name: "SecretDeleteError"}
	ErrSecretParse           = &SecretBinError{Name: "SecretParseError"}
	ErrSecretPolicy          = &SecretBinError{Name: "SecretPolicyError"}
	ErrSecretSizeLimit       = &SecretBinError{Name: "SecretSizeLimitError"}
)

type SecretBinError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// Error marks the SecretBinError as an error type.
func (e *SecretBinError) Error() string {
	return fmt.Sprintf("%s: %s", e.Name, e.Message)
}

// Is checks if the error matches the target error.
func (e *SecretBinError) Is(target error) bool {
	if target == nil {
		return false
	}

	if other, ok := target.(*SecretBinError); ok {
		return e.Name == other.Name
	}

	return false
}
