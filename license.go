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

// Customer godoc.
type Customer struct {
	Name               string
	Country            string
	City               string
	Organization       string
	OrganizationalUnit string
}

type asnSignedLicense struct {
	Raw                asn1.RawContent
	ProductName        string       `asn1:"optional,application,tag:0"`
	SerialNumber       string       `asn1:"optional,application,tag:1"`
	Customer           asnCustomer  `asn1:"optional,private,omitempty"`
	ValidFrom          int64        `asn1:"optional,default:0"`
	ValidUntil         int64        `asn1:"optional,default:0"`
	MinVersion         int64        `asn1:"optional,default:0"`
	MaxVersion         int64        `asn1:"optional,default:0"`
	Features           []asnFeature `asn1:"optional,omitempty"`
	AuthorityKeyID     []byte
	SignatureAlgorithm asn1.ObjectIdentifier
}

type asnCustomer struct {
	Raw                asn1.RawContent
	Name               string `asn1:"optional,tag:0"`
	Country            string `asn1:"optional,tag:1"`
	City               string `asn1:"optional,tag:2"`
	Organization       string `asn1:"optional,tag:3"`
	OrganizationalUnit string `asn1:"optional,tag:4"`
}

type asnFeature struct {
	Raw    asn1.RawContent
	Oid    asn1.ObjectIdentifier
	Expire int64 `asn1:"optional,tag:1"`
	Limit  int64 `asn1:"optional,tag:2"`
}

type asnSignature struct {
	AlgorithmIdentifier asn1.ObjectIdentifier
	Value               asn1.BitString
}

type asnLicense struct {
	License   asnSignedLicense
	Signature asnSignature
}

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
		Customer: asnCustomer{
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
		SignatureAlgorithm: signatureAlgorithm,
	}

	for _, feature := range template.Features {
		tbsLicense.Features = append(tbsLicense.Features, asnFeature{Oid: feature.Oid, Limit: feature.Limit})
	}

	signature, err := signAsnObject(tbsLicense, key, hashFunc)
	if err != nil {
		return nil, err
	}

	licObject := asnLicense{
		License: tbsLicense,
		Signature: asnSignature{
			AlgorithmIdentifier: tbsLicense.SignatureAlgorithm,
			Value:               asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
		},
	}

	return asn1.Marshal(licObject)
}

// Load Load license from asn encoded file.
func Load(asn1Data []byte, publicKey interface{}, validator ValidateSN) (*License, error) {
	var licObject asnLicense

	rest, err := asn1.Unmarshal(asn1Data, &licObject)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("license: mallformed data")
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

func setLicenseDetails(tmpl asnSignedLicense, validator ValidateSN) (*License, error) {
	if validator != nil {
		err := validator(tmpl.ProductName, tmpl.SerialNumber, tmpl.ValidFrom, tmpl.ValidUntil, tmpl.MinVersion, tmpl.MaxVersion)
		if err != nil {
			return nil, err
		}
	}

	l := License{
		ProductName:  tmpl.ProductName,
		SerialNumber: tmpl.SerialNumber,
		ValidFrom:    time.Time{},
		ValidUntil:   time.Time{},
		MinVersion:   Version(tmpl.MinVersion),
		MaxVersion:   Version(tmpl.MaxVersion),
		Customer: Customer{
			Name:               tmpl.Customer.Name,
			Country:            tmpl.Customer.Country,
			City:               tmpl.Customer.City,
			Organization:       tmpl.Customer.Organization,
			OrganizationalUnit: tmpl.Customer.OrganizationalUnit,
		},
		Features: []Feature{},
	}

	if tmpl.ValidFrom > 0 {
		l.ValidFrom = time.Unix(tmpl.ValidFrom, 0)
	}

	if tmpl.ValidUntil > 0 {
		l.ValidUntil = time.Unix(tmpl.ValidUntil, 0)
	}

	// Set features info
	for _, feature := range tmpl.Features {
		l.Features = append(l.Features, Feature{Oid: feature.Oid, Limit: feature.Limit})
	}

	return &l, nil
}
