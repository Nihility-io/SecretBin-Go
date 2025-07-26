package secretbin

import (
	"fmt"
)

type Client interface {
	// Config returns information about the SecretBin server.
	Config() *Config

	// SubmitSecret creates a new secret inside SecretBin and returns the access URL for said secret.
	SubmitSecret(secret Secret, options Options) (string, error)
}

type client struct {
	endpoint string
	config   *Config
}

// New creates a new SecretBin client for the given endpoint.
// It retrieves the API information and configuration from the server to initialize the client.
func New(endpoint string) (Client, error) {
	c := client{endpoint: endpoint}

	info, err := c.getApiInfo()
	if err != nil {
		return nil, err
	}

	config, err := c.getApiConfig()
	if err != nil {
		return nil, err
	}

	c.config = &Config{
		Name:           config.Branding.AppName,
		Endpoint:       c.endpoint,
		Version:        info.Version,
		DefaultExpires: config.Defaults.Expires,
	}
	if banner := config.Banner; banner.Enabled {
		c.config.Banner = &Banner{
			Type: banner.Type,
			Text: banner.Text["en"],
		}
	}
	c.config.Expires = config.Expires
	if c.config.Expires == nil {
		c.config.Expires = map[string]Expires{}
	}

	return &c, nil
}

type Options struct {
	// Password is used as an additional security step along the the encryption key (optional)
	Password string

	// Expires is the expiration time for the secret.
	//
	// Use [Client.Config().Expires] to get the available options.
	Expires string

	// BurnAfter indicates after how many reads the secret should be deleted.
	//
	// 0 means no burn after reading.
	BurnAfter uint
}

// Config returns information about the SecretBin server.
func (c *client) Config() *Config {
	return c.config
}

// SubmitSecret creates a new secret inside SecretBin and returns the access URL for said secret.
func (c *client) SubmitSecret(secret Secret, options Options) (string, error) {
	// If no expiration time is set, use the server's default one.
	if options.Expires == "" {
		options.Expires = c.config.DefaultExpires
	}

	// Validate the expiration time against the server's available options.
	if _, ok := c.config.Expires[options.Expires]; !ok {
		return "", &SecretBinError{
			Name:    ErrInvalidExpirationTime.Name,
			Message: fmt.Sprintf("Invalid expiration time '%s'. Valid options are: %v", options.Expires, c.config.ExpireOptionsSorted()),
		}
	}

	// Encrypt the secret with the provided password and return the key and encrypted data.
	key, enc, err := secret.encrypted(options.Password)
	if err != nil {
		return "", err
	}

	// Create the payload for the secret to be posted to SecretBin.
	pl := postSecretPayload{
		Expires:           options.Expires,
		BurnAfter:         int(options.BurnAfter),
		PasswordProtected: options.Password != "",
		Data:              enc,
	}

	// The SecretBin API uses -1 to indicate no burn after reading.
	// The value 0 is used to indicate that the secret should not be
	// deleted by the server garbage collector.
	if pl.BurnAfter == 0 {
		pl.BurnAfter = -1
	}

	// Post the secret to the SecretBin server and retrieve the result.
	r, err := c.postSecret(&pl)
	if err != nil {
		return "", err
	}

	// Construct the URL to access the secret using the secret ID and the encryption key.
	return fmt.Sprintf("%s/secret/%s#%s", c.endpoint, r.ID, key), nil
}
