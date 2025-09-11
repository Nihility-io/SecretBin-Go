package secretbin

import (
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/Masterminds/semver/v3"
)

type Config struct {
	Name           string             // Name of the SecretBin instance
	Endpoint       string             // Endpoint URL of the SecretBin server
	Version        *semver.Version    // Version of the SecretBin server
	Banner         *Banner            // Optional banner displayed by the server
	Expires        map[string]Expires // Available expiration options for secrets
	DefaultExpires string             // Default expiration option for secrets
}

// ExpiresSorted returns an iterator that yields expiration options sorted by their duration.
func (c *Config) ExpiresSorted() iter.Seq2[string, Expires] {
	return func(yield func(string, Expires) bool) {
		valid := slices.Collect(maps.Keys(c.Expires))
		slices.SortFunc(valid, func(a string, b string) int {
			if c.Expires[a].Seconds < c.Expires[b].Seconds {
				return -1
			}

			return 1
		})
		for _, k := range valid {
			if !yield(k, c.Expires[k]) {
				return
			}
		}
	}
}

// ExpiresOptionsSorted returns a slice of expiration option names sorted by their duration.
func (c *Config) ExpireOptionsSorted() []string {
	valid := slices.Collect(maps.Keys(c.Expires))
	slices.SortFunc(valid, func(a string, b string) int {
		if c.Expires[a].Seconds < c.Expires[b].Seconds {
			return -1
		}

		return 1
	})

	return valid
}

type Banner struct {
	Type string `json:"type"` // Type of the banner ("info", "warning", "error")
	Text string `json:"text"` // Text content of the banner
}

type Expires struct {
	Count   int    `json:"count"`   // Number of units for this expiration option
	Unit    string `json:"unit"`    // Unit of time for this expiration option (e.g., "hr", "d", "w", "m", "y")
	Seconds int    `json:"seconds"` // Duration in seconds for this expiration option
}

// String returns a human-readable representation of the expiration option.
func (e Expires) String() string {
	s := ""
	if e.Count > 1 {
		s = "s"
	}

	return fmt.Sprintf("%d %s%s (%ds)", e.Count, e.Unit, s, e.Seconds)
}
