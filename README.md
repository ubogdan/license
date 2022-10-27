# license
[![Build Status](https://github.com/ubogdan/license/actions/workflows/unit-test.yml/badge.svg?branch=master)](https://github.com/features/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/ubogdan/license)](https://goreportcard.com/report/github.com/ubogdan/license)
[![Go Doc](https://godoc.org/github.com/ubogdan/license?status.svg)](https://godoc.org/github.com/ubogdan/license)

License is a library that helps generate licenses that can be validated offline

Generate a license
------------------

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"log"
	"time"

	"github.com/ubogdan/license"
)

func main() {
	// Create basic license Data
	licenseData := license.License{
		ProductName:  "Your Product Name",
		SerialNumber: "Some Serial Number",
		MinVersion:   10000,                               // Valid from v0.0.1
		MaxVersion:   200000000,                           // Valid until v2.0.0
		ValidFrom:    time.Now(),                          // Valid from today
		ValidUntil:   time.Now().Add(30 * 24 * time.Hour), // Valid for 30 days
		Features: []license.Feature{
			{
				Oid:         []int{1, 3, 6, 1, 3, 1, 1},
				Description: "Some Feature",
				Limit:       5,
			},
		},
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Generate license
	licenseBytes, err := license.CreateLicense(&licenseData, signer)
	if err != nil {
		log.Fatalf("Failed to create license: %v", err)
	}

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "LICENSE",
		Bytes: licenseBytes,
	})

	log.Printf("License: %s", string(data))
}

```

Verify a license
------------------
```go
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"time"

	"github.com/ubogdan/license"
)

const (
	productName = "Your Product Name"
	version     = "1.2.3"
)

func main() {
	// Read license data from file
	pemData, err := ioutil.ReadFile("/etc/product_name/license.pem")
	if err != nil {
		log.Fatalf("Failed to read license: %v", err)
	}

	pemBlock, r := pem.Decode(pemData)
	if pemBlock == nil {
		log.Fatalf("Failed to decode license: %v", r)
	}

	publicDer, err := hex.DecodeString("YOUR_PUBLIC_KEY_HEX")
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	publicEcc, err := x509.ParsePKIXPublicKey(publicDer)
	if err != nil {
		log.Printf("Failed to parse public key: %v", err)
	}

	ver, err := license.NewVersion(version)
	if err != nil {
		log.Fatalf("Failed to parse version: %v", err)
	}

	snValidator := func(product, serial string, validFrom, validUntil, minVersion, maxVersion int64) error {
		if product != productName {
			return errors.New("invalid product name")
		}

		if validFrom > time.Now().Unix() {
			return errors.New("license is not valid yet")
		}

		if validUntil < time.Now().Unix() {
			return errors.New("license is expired")
		}

		if minVersion > int64(ver) || int64(ver) > maxVersion {
			return errors.New("invalid version")
		}

		// Validate serial number here

		return nil
	}

	license, err := license.Load(pemBlock.Bytes, publicEcc, snValidator)
	if err != nil {
		log.Fatalf("Failed to load license: %v", err)
	}

	log.Printf("License: %v", license)
}

```