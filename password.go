package secretbin

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

const (
	Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Lowercase = "abcdefghijklmnopqrstuvwxyz"
	Digits    = "0123456789"
	Symbols   = "~!@#%&*_-+=,.<>?"
)

var (
	ErrInvalidPasswordLength = errors.New("invalid password length; must be greater than 6")
	ErrInvalidCharacterSet   = errors.New(
		"at least one character set (uppercase, lowercase, digits, symbols) must be selected")
)

// PasswordOptions defines the options for generating a password.
type PasswordOptions struct {
	Uppercase bool
	Lowercase bool
	Digits    bool
	Symbols   bool
	Length    int
}

// GeneratePassword generates a secure random password based on the provided options.
// It ensures that at least one character from each selected set is included.
// If no character sets are selected or the length is below 6, it returns an error.
func GeneratePassword(options PasswordOptions) (string, error) {
	if options.Length <= 0 {
		options.Length = 16 // Default length
	}

	if options.Length <= 6 {
		return "", ErrInvalidPasswordLength
	}

	if !options.Uppercase && !options.Lowercase && !options.Digits && !options.Symbols {
		return "", ErrInvalidCharacterSet
	}

	// Collect selected character sets
	var characterSets []string
	if options.Uppercase {
		characterSets = append(characterSets, Uppercase)
	}
	if options.Lowercase {
		characterSets = append(characterSets, Lowercase)
	}
	if options.Digits {
		characterSets = append(characterSets, Digits)
	}
	if options.Symbols {
		characterSets = append(characterSets, Symbols)
	}

	passwordChars := make([]rune, 0, options.Length)

	// Ensure the password has one character from each set
	for _, set := range characterSets {
		idx, _ := randomInt(len(set))
		passwordChars = append(passwordChars, rune(set[idx]))
	}

	// Fill remaining characters with random choice from all sets combined
	allChars := strings.Join(characterSets, "")
	for len(passwordChars) < options.Length {
		idx, _ := randomInt(len(allChars))
		passwordChars = append(passwordChars, rune(allChars[idx]))
	}

	// Shuffle the password characters to avoid predictable patterns
	for i := len(passwordChars) - 1; i > 0; i-- {
		j, _ := randomInt(i + 1)
		passwordChars[i], passwordChars[j] = passwordChars[j], passwordChars[i]
	}

	return string(passwordChars), nil
}

// randomInt generates a secure random integer in the range [0, max).
func randomInt(max int) (int, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}

	return int(nBig.Int64()), nil
}
