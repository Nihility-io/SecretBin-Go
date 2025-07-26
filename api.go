package secretbin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// JSON result for: GET /api/info
type apiInfo struct {
	Version string `json:"version"`
}

// Partial JSON result for: GET /api/config
type apiConfig struct {
	Banner struct {
		Enabled bool              `json:"enabled"`
		Type    string            `json:"type"`
		Text    map[string]string `json:"text"`
	} `json:"banner"`
	Branding struct {
		AppName string `json:"appName"`
	} `json:"branding"`
	Defaults struct {
		Expires string `json:"expires"`
	} `json:"defaults"`
	Expires map[string]Expires `json:"expires"`
}

// Payload for: POST /api/secret
type postSecretPayload struct {
	Data              string `json:"data"`
	Expires           string `json:"expires"`
	BurnAfter         int    `json:"burnAfter"`
	PasswordProtected bool   `json:"passwordProtected"`
}

// JSON result for: POST /api/secret
type postSecretResult struct {
	ID string `json:"id"`
}

// url constructs the full URL for the SecretBin API endpoint
func (c *client) url(path string) string {
	return fmt.Sprintf("%s%s", c.endpoint, path)
}

// getApiInfo retrieves the version information from the SecretBin server
func (c *client) getApiInfo() (*apiInfo, error) {
	return apiCall[apiInfo](http.MethodGet, c.url("/api/info"), nil)
}

// getApiConfig retrieves the configuration from the SecretBin server
// This includes banner settings, branding, default expiration, and available expiration times.
func (c *client) getApiConfig() (*apiConfig, error) {
	return apiCall[apiConfig](http.MethodGet, c.url("/api/config"), nil)
}

// postSecret submits a new secret to the SecretBin server
func (c *client) postSecret(pl *postSecretPayload) (*postSecretResult, error) {
	return apiCall[postSecretResult](http.MethodPost, c.url("/api/secret"), pl)
}

// apiCall is a generic function to make API calls to the SecretBin server
// It handles the HTTP request, response decoding, and error handling.
// T is the expected type of the response body.
// If the response status code is not 200, it returns a SecretBinError.
func apiCall[T any](method string, url string, payload any) (*T, error) {
	// Create the request body if payload is not nil
	var body io.Reader = nil
	if payload != nil {
		buff := bytes.NewBuffer(nil)
		if err := json.NewEncoder(buff).Encode(payload); err != nil {
			return nil, err
		}
		body = buff
	}

	// Create the HTTP request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Set the content type header if payload is provided
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Contact the SecretBin API
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	// Check if the response is an error
	if res.StatusCode != 200 {
		sbErr := SecretBinError{}
		if err := json.NewDecoder(res.Body).Decode(&sbErr); err != nil {
			return nil, err
		}
		return nil, &sbErr
	}

	// Decode the response body into the expected type T
	var v T
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}

	return &v, nil
}
