package license

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"time"
)

// License godoc
type License struct {
	ProductName  string    `json:"product"`
	SerialNumber string    `json:"serial"`
	Customer     Customer  `json:"customer"`
	ValidFrom    time.Time `json:"valid_from,omitempty"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	MinVersion   int64     `json:"min_version,omitempty"`
	MaxVersion   int64     `json:"max_version,omitempty"`
	Features     []Feature `json:"features"`

	// Handle serial number validation during Load
	SerialNumberValidator func(product, serial string) error
	knownFeatures         map[string]string
	signature             asnSignature
}

// Customer godoc
type Customer struct {
	Name               string
	Country            string
	City               string
	Organization       string
	OrganizationalUnit string
}

// Feature godoc
type Feature struct {
	Oid         asn1.ObjectIdentifier `json:"-"`
	Description string                `json:"description"`
	Expire      int64                 `json:"expire,omitempty"`
	Limit       int64                 `json:"limit"`
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
		MinVersion:         template.MinVersion,
		MaxVersion:         template.MaxVersion,
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
	licObject := &asnLicense{
		License: tbsLicense,
		Signature: asnSignature{
			AlgorithmIdentifier: tbsLicense.SignatureAlgorithm,
			Value:               asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
		},
	}

	return asn1.Marshal(*licObject)
}

// Load Load license from asn encoded file.
func (l *License) Load(asn1Data []byte, publicKey interface{}) error {
	var licObject asnLicense
	rest, err := asn1.Unmarshal(asn1Data, &licObject)
	if err != nil || len(rest) != 0 {
		return errors.New("license: mallformed data")
	}
	digest, hashFunc, err := auhtorityhashFromAlgorithm(publicKey, licObject.License)
	if err != nil {
		return err
	}
	err = checkSignature(digest, licObject.Signature.Value.Bytes, hashFunc, publicKey)
	if err != nil {
		return err
	}
	l.signature = licObject.Signature

	return l.setSoftwareInfo(licObject.License)
}

func (l *License) setSoftwareInfo(template asnSignedLicense) error {
	if l.SerialNumberValidator != nil {
		err := l.SerialNumberValidator(template.ProductName, template.SerialNumber)
		if err != nil {
			return err
		}
	}
	l.ProductName = template.ProductName
	l.SerialNumber = template.SerialNumber
	l.ValidFrom = time.Time{}
	if template.ValidFrom > 0 {
		l.ValidFrom = time.Unix(template.ValidFrom, 0)
	}
	l.ValidUntil = time.Time{}
	if template.ValidUntil > 0 {
		l.ValidUntil = time.Unix(template.ValidUntil, 0)
	}
	l.MinVersion = template.MinVersion
	l.MaxVersion = template.MaxVersion

	// Set customer info
	l.Customer.Name = template.Customer.Name
	l.Customer.Country = template.Customer.Country
	l.Customer.City = template.Customer.City
	l.Customer.Organization = template.Customer.Organization
	l.Customer.OrganizationalUnit = template.Customer.OrganizationalUnit

	// Set features info
	l.Features = []Feature{}
	for _, feature := range template.Features {
		description, found := l.knownFeatures[feature.Oid.String()]
		if !found {
			continue
		}
		l.Features = append(l.Features, Feature{Description: description, Oid: feature.Oid, Limit: feature.Limit})
	}
	return nil
}
