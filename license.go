package license

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

var (
	oidLicenseMinVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 3, 1, 1}
	oidLicenseMaxVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 3, 1, 2}
)

type License struct {
	ProductName   string            `json:"product"`
	SerialNumber  string            `json:"serial"`
	Customer      Customer          `json:"customer"`
	ValidFrom     time.Time         `json:"valid_from,omitempty" asn1:"default:0"`
	ValidUntil    time.Time         `json:"valid_until,omitempty" asn1:"default:0"`
	MinVersion    int64             `json:"min_version,omitempty" asn1:"default:0"`
	MaxVersion    int64             `json:"max_version,omitempty" asn1:"default:0"`
	Features      []Feature         `json:"features"`
	knownFeatures map[string]string `json:"features"`
	signature     asnSignature
}

type Feature struct {
	Oid         asn1.ObjectIdentifier `json:"-"`
	Description string                `json:"description"`
	Limit       int64                 `json:"limit"`
}

type SerialNumberValidator func(license *License) error

type asnSignedLicense struct {
	ProductName        string
	SerialNumber       string
	Customer           Customer
	Validity           Validity
	Features           []asnFeature
	AuthorityKeyId     []byte
	SignatureAlgorithm pkix.AlgorithmIdentifier
}

type asnFeature struct {
	Oid   asn1.ObjectIdentifier
	Limit int64 `asn1:"optional,omitmepty"`
}

type asnSignature struct {
	pkix.AlgorithmIdentifier
	Value asn1.BitString
}

type asnLicense struct {
	License   asnSignedLicense
	Signature asnSignature
}

func CreateLicense(template *License, key crypto.Signer) ([]byte, error) {

	if key == nil {
		return nil, errors.New("license: private key is nil")
	}
	publicKey := key.Public()
	authorityKeyId, err := publicKeySignature(publicKey)
	if err != nil {
		return nil, err
	}
	hashFunc, signatureAlgorithm, err := hashFromPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	var features []asnFeature

	if template.MinVersion > 0 {
		features = append(features, asnFeature{Oid: oidLicenseMinVersion, Limit: template.MinVersion})
	}
	if template.MaxVersion > 0 {
		features = append(features, asnFeature{Oid: oidLicenseMaxVersion, Limit: template.MaxVersion})
	}
	for _, feature := range template.Features {
		features = append(features, asnFeature{Oid: feature.Oid, Limit: feature.Limit})
	}
	tbsLicense := asnSignedLicense{
		ProductName:        template.ProductName,
		SerialNumber:       template.SerialNumber,
		Customer:           template.Customer,
		Validity:           Validity{From: template.ValidFrom, Until: template.ValidUntil},
		Features:           features,
		AuthorityKeyId:     authorityKeyId,
		SignatureAlgorithm: signatureAlgorithm,
	}

	digest, err := asnObjectSignature(tbsLicense, hashFunc.New())
	if err != nil {
		return nil, err
	}
	var signature []byte
	signature, err = key.Sign(rand.Reader, digest, hashFunc)
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

// TODO snValidate Handler
func (l *License) Load(asn1Data []byte, publicKey interface{}) error {
	var licObject asnLicense
	if rest, err := asn1.Unmarshal(asn1Data, &licObject); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("license: trailing data")
	}

	authorityKeyId, err := publicKeySignature(publicKey)
	if err != nil {
		return err
	}
	license := licObject.License

	if !bytes.Equal(authorityKeyId, license.AuthorityKeyId) {
		return errors.New("license: invalid AuthorityId")
	}

	hashFunc, err := hashFuncFromAlgorithm(license.SignatureAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	digest, err := asnObjectSignature(license, hashFunc.New())
	if err != nil {
		return err
	}

	err = checkSignature(digest, licObject.Signature.Value.Bytes, hashFunc, publicKey)
	if err != nil {
		return err
	}

	l.ProductName = license.ProductName
	l.SerialNumber = license.SerialNumber

	if license.Validity.IsValid(time.Now()) {
		l.ValidFrom = license.Validity.From
		l.ValidUntil = license.Validity.Until
	}
	l.Customer = license.Customer

	for _, feature := range license.Features {
		switch {
		case feature.Oid.Equal(oidLicenseMinVersion):
			l.MinVersion = feature.Limit
		case feature.Oid.Equal(oidLicenseMaxVersion):
			l.MaxVersion = feature.Limit
		default:
			description, found := l.knownFeatures[feature.Oid.String()]
			if !found {
				continue
			}
			l.Features = append(l.Features, Feature{Description: description, Oid: feature.Oid, Limit: feature.Limit})
		}
	}

	l.signature = licObject.Signature

	return nil
}
