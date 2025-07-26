# SecretBin-Go
This module allows for automatic secret creation in [SecretBin](https://github.com/Nihility-io/SecretBin). Note however this module currently only support creating AES256-GCM secrets. XChaCha20 is currently not supported.

## Usage
``` go
package main

import (
    "fmt"
	secretbin "github.com/Nihility-io/SecretBin-Go/v2"
)

func main() {
    // Connect to the SecretBin server
    sb, err := secretbin.New("https://secretbin.example.com")
    if err != nil {
        panic(err)
    }

    // Create a secret with arguments joined into a single message.
    secret := secretbin.Secret{Message: "Hello World"}

    // Append files to the secret
    if err := secret.AddFileAttachment("myfile.pdf"); err != nil {
        panic(err)
    }

    // Submit the secret with the specified options to SecretBin.
    // This will encrypt the secret and return a link to access it.
    link, err := sb.SubmitSecret(secret, secretbin.Options{
        Password:  "abc",
        Expires:   "2w",
        BurnAfter: 1,
    })
    if err != nil {
        panic(err)
    }

    // Print the link to the created secret.
    fmt.Println(link)
}
```