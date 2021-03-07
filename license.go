package license

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"time"
)

// License godoc.
type License struct {
	ProductName  string    `json:"product"`
	SerialNumber string    `json:"serial"`
	Customer     Customer  `json:"customer"`
	ValidFrom    time.Time `json:"valid_from,omitempty"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	MinVersion   Version   `json:"min_version,omitempty"`
	MaxVersion   Version   `json:"max_version,omitempty"`
	Features     []Feature `json:"features"`
}

// ValidateSN godoc.
type ValidateSN func(product, serial string, validFrom, validUntil, minVersion, maxVersion int64) error

type asnSignedLicense struct {
	Raw                asn1.RawContent
	ProductName        string    `asn1:"optional,application,tag:0"`
	SerialNumber       string    `asn1:"optional,application,tag:1"`
	Customer           Customer  `asn1:"optional,private,omitempty"`
	ValidFrom          int64     `asn1:"optional,default:0"`
	ValidUntil         int64     `asn1:"optional,default:0"`
	MinVersion         int64     `asn1:"optional,default:0"`
	MaxVersion         int64     `asn1:"optional,default:0"`
	Features           []Feature `asn1:"optional,omitempty"`
	AuthorityKeyID     []byte
	SignatureAlgorithm asn1.ObjectIdentifier
}

type asnSignature struct {
	AlgorithmIdentifier asn1.ObjectIdentifier
	Value               asn1.BitString
}

type asnLicense struct {
	License   asnSignedLicense
	Signature asnSignature
}

const (
	byteSize = 8
)

// CreateLicense godoc.
func CreateLicense(template *License, key crypto.Signer) ([]byte, error) {
	if key == nil {
		return nil, errors.New("license: private key is nil")
	}

	authorityKeyID, hashFunc, signatureAlgorithm, err := auhtorityhashFromPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	tbsLicense := asnSignedLicense{
		ProductName:  template.ProductName,
		SerialNumber: template.SerialNumber,
		Customer: Customer{
			Name:               template.Customer.Name,
			Country:            template.Customer.Country,
			City:               template.Customer.City,
			Organization:       template.Customer.Organization,
			OrganizationalUnit: template.Customer.OrganizationalUnit,
		},
		ValidFrom:          template.ValidFrom.Unix(),
		ValidUntil:         template.ValidUntil.Unix(),
		MinVersion:         int64(template.MinVersion),
		MaxVersion:         int64(template.MaxVersion),
		AuthorityKeyID:     authorityKeyID,
		Features:           template.Features,
		SignatureAlgorithm: signatureAlgorithm,
	}

	signature, err := signAsnObject(tbsLicense, key, hashFunc)
	if err != nil {
		return nil, err
	}

	licObject := asnLicense{
		License: tbsLicense,
		Signature: asnSignature{
			AlgorithmIdentifier: tbsLicense.SignatureAlgorithm,
			Value:               asn1.BitString{Bytes: signature, BitLength: len(signature) * byteSize},
		},
	}

	return asn1.Marshal(licObject)
}

// Load Load license from asn encoded file.
func Load(asn1Data []byte, publicKey interface{}, validator ValidateSN) (*License, error) {
	var licObject asnLicense

	rest, err := asn1.Unmarshal(asn1Data, &licObject)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("license: malformed data")
	}

	digest, hashFunc, err := auhtorityhashFromAlgorithm(publicKey, licObject.License)
	if err != nil {
		return nil, err
	}

	err = checkSignature(digest, licObject.Signature.Value.Bytes, hashFunc, publicKey)
	if err != nil {
		return nil, err
	}

	return setLicenseDetails(licObject.License, validator)
}

func setLicenseDetails(license asnSignedLicense, validator ValidateSN) (*License, error) {
	if validator != nil {
		err := validator(license.ProductName, license.SerialNumber,
			license.ValidFrom, license.ValidUntil, license.MinVersion, license.MaxVersion)
		if err != nil {
			return nil, err
		}
	}

	l := License{
		ProductName:  license.ProductName,
		SerialNumber: license.SerialNumber,
		ValidFrom:    time.Time{},
		ValidUntil:   time.Time{},
		MinVersion:   Version(license.MinVersion),
		MaxVersion:   Version(license.MaxVersion),
		Customer: Customer{
			Name:               license.Customer.Name,
			Country:            license.Customer.Country,
			City:               license.Customer.City,
			Organization:       license.Customer.Organization,
			OrganizationalUnit: license.Customer.OrganizationalUnit,
		},
		Features: []Feature{},
	}

	if license.ValidFrom > 0 {
		l.ValidFrom = time.Unix(license.ValidFrom, 0)
	}

	if license.ValidUntil > 0 {
		l.ValidUntil = time.Unix(license.ValidUntil, 0)
	}

	// Set features info
	for _, feature := range license.Features {
		l.Features = append(l.Features, Feature{Oid: feature.Oid, Limit: feature.Limit})
	}

	return &l, nil
}
