package license

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

var (
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidLicenseMinVersion        = asn1.ObjectIdentifier{1, 3, 6, 1, 3, 1, 1}
	oidLicenseMaxVersion        = asn1.ObjectIdentifier{1, 3, 6, 1, 3, 1, 2}
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
	Algorithm pkix.AlgorithmIdentifier
	Value     asn1.BitString
}

type asnLicense struct {
	License   asnSignedLicense
	Signature asnSignature
}

// TODO snValidate Handler
func ParseLicense(asn1Data []byte) (*License, error) {
	var lic asnLicense
	if rest, err := asn1.Unmarshal(asn1Data, &lic); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("license: trailing data")
	}

	// TODO Validate signature

	license := &License{
		ProductName:  lic.License.ProductName,
		SerialNumber: lic.License.SerialNumber,
		Customer:     lic.License.Customer,
		ValidFrom:    lic.License.Validity.From,
		ValidUntil:   lic.License.Validity.Until,
		signature:    lic.Signature,
	}

	for _, feature := range lic.License.Features {
		switch {
		case feature.Oid.Equal(oidLicenseMinVersion):
			license.MinVersion = feature.Limit

		case feature.Oid.Equal(oidLicenseMaxVersion):
			license.MaxVersion = feature.Limit

		default:

		}
	}

	return license, nil
}

func CreateLicense(template *License, key crypto.Signer) ([]byte, error) {

	if key == nil {
		return nil, errors.New("license: private key is nil")
	}

	var signatureAlgorithm pkix.AlgorithmIdentifier
	var hashFunc crypto.Hash

	publicKey := key.Public()

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		hashFunc = crypto.SHA256
		signatureAlgorithm.Algorithm = oidSignatureSHA256WithRSA
		signatureAlgorithm.Parameters = asn1.NullRawValue

	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			signatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA512
		default:
			return nil, errors.New("license: unknown elliptic curve")
		}

	default:
		return nil, errors.New("license: only RSA and ECDSA keys supported")
	}

	sigBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	authorityHash := sha1.New()
	_, err = authorityHash.Write(sigBytes)
	if err != nil {
		return nil, err
	}

	authorityKeyId, err := asn1.Marshal(authorityHash.Sum(nil))
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
		//
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

	licObject, err := signLicense(tbsLicense, hashFunc)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(*licObject)

}

// TODO snValidate Handler
func (l *License) Load(asn1Data []byte) error {
	var lic asnLicense
	if rest, err := asn1.Unmarshal(asn1Data, &lic); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("license: trailing data")
	}

	// TODO Validate signature

	l.ProductName = lic.License.ProductName

	l.SerialNumber = lic.License.SerialNumber

	if lic.License.Validity.IsValid(time.Now()) {
		l.ValidFrom = lic.License.Validity.From
		l.ValidUntil = lic.License.Validity.Until
	}

	l.Customer = lic.License.Customer

	for _, feature := range lic.License.Features {
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

	l.signature = lic.Signature

	return nil
}

func signLicense(lic asnSignedLicense, hash crypto.Hash) (*asnLicense, error) {

	sLicContent, err := asn1.Marshal(lic)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	_, err = h.Write(sLicContent)
	if err != nil {
		return nil, err
	}

	signature := h.Sum(nil)

	return &asnLicense{
		License: lic,
		Signature: asnSignature{
			Algorithm: lic.SignatureAlgorithm,
			Value:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
		},
	}, nil
}
