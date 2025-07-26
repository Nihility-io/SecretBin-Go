package secretbin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"os"
	"path"
	"path/filepath"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"
)

type Secret struct {
	Message     string        `json:"message"`     // Text content of the secret
	Attachments []*Attachment `json:"attachments"` // Optional file attachments of the secret
}

type Attachment struct {
	Name        string `json:"name"`        // Filename of the attachment
	ContentType string `json:"contentType"` // MIME type of the attachment
	Data        []byte `json:"data"`        // Binary data of the attachment
}

// AddAttachment adds an attachment to the secret content.
// If the content type is not provided, it will be guessed based on the file extension.
func (s *Secret) AddAttachment(name string, contentType string, data []byte) {
	if s.Attachments == nil {
		s.Attachments = []*Attachment{}
	}

	if contentType == "" {
		contentType = mime.TypeByExtension(path.Ext(name))
	}

	s.Attachments = append(s.Attachments, &Attachment{
		Name:        name,
		ContentType: contentType,
		Data:        data,
	})
}

// AddFileAttachment reads a file from the given path and adds it as an attachment to the secret content.
// The content type is guessed based on the file extension.
func (s *Secret) AddFileAttachment(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	s.AddAttachment(filepath.Base(path), "", b)

	return nil
}

// encrypted encrypts the secret content using AES-256-GCM and returns the base58 encoded key and a crypto URL.
func (s *Secret) encrypted(password string) (string, string, error) {
	// Attachments is not allowed to be nil by the SecretBin API, so we ensure it is initialized
	if s.Attachments == nil {
		s.Attachments = []*Attachment{}
	}

	// Ensure all attachments have a content type set
	// If not set, guess the content type based on the file extension
	for _, attachment := range s.Attachments {
		if attachment.ContentType == "" {
			attachment.ContentType = mime.TypeByExtension(path.Ext(attachment.Name))
		}
	}

	// Marshal the secret content to JSON
	data, err := json.Marshal(s)
	if err != nil {
		return "", "", err
	}

	// A random base key which is used to derive the actual key for AES encryption
	baseKey := make([]byte, 32)
	if _, err := rand.Read(baseKey); err != nil {
		return "", "", err
	}

	// Generate a random IV (initialization vector) for AES-GCM
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", "", err
	}

	// Generate a random salt for the PBKDF2 key derivation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	// Set the number of iterations for PBKDF2 as recommended by OWASP
	iter := 210000

	key := pbkdf2.Key(append(baseKey, []byte(password)...), salt, iter, 32, sha512.New)

	// Create a new AES cipher using the derived key
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	aead, err := cipher.NewGCM(c)
	if err != nil {
		return "", "", err
	}

	// Encrypt the data using AES-GCM
	enc := aead.Seal(nil, iv, data, nil)

	// Create the crypto URL with the necessary parameters
	// This includes the algorithm, key algorithm, nonce (IV), salt, iterations, and
	cryptoURL := fmt.Sprintf("crypto://?algorithm=AES256-GCM&key-algorithm=pbkdf2&nonce=%s&salt=%s&iter=%d&hash=SHA-512#", base58.Encode(iv), base58.Encode(salt), iter) + base64.StdEncoding.EncodeToString(enc)

	// Encode the base key in base58 for the URL
	return base58.Encode(baseKey), cryptoURL, nil
}
