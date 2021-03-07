package license

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testEccPrivate = "MHcCAQEEIMVSIK6PTSva0pJifUoFWU5vNUtsZRAL76nxIA2GT/CroAoGCCqGSM49AwEHoUQ" +
		"DQgAEPG9ZZcLgHiAWGLKScyJnnEzX6gCqTVIc1CQTf77LgxHTc1mkDKh8xJ7VQUh+6od0h9ce5xrHcnJ0VB3rvBVWMQ=="
	testLicenseProduct                    = "Test Product"
	testLicenseSerial                     = "05717-43D86-81C08-D6130-F090C"
	testLicenseMinVersion                 = 100        // 0.10.0
	testLicenseMaxVersion                 = 1000       // 1.00.0
	testLicenseValidFrom                  = 1546300800 // 2019 Jan 1
	testLicenseValidUntil                 = 1577664000 // 2019 Dec 30
	testLicenseCustomerName               = "Test Customer"
	testLicenseCustomerCountry            = "US"
	testLicenseCustomerCity               = "New York"
	testLicenseCustomerOrganization       = "TEST LLC"
	testLicenseCustomerOrganizationalUnit = "Sales Department"
)

var (
	oidLicenseMinVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 3, 1, 1}
	oidLicenseMaxVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 3, 1, 2}
)

type CryptoSigner struct {
	PublicKey crypto.PublicKey
	SignFunc  func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (c CryptoSigner) Public() crypto.PublicKey {
	return c.PublicKey
}

func (c CryptoSigner) Sign(rand io.Reader, data []byte, hash crypto.SignerOpts) ([]byte, error) {
	return c.SignFunc(rand, data, hash)
}

func TestCreateLicense(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		Data       *License
		Key        crypto.Signer
		ShouldFail bool
	}{
		{
			Data:       &License{},
			Key:        nil,
			ShouldFail: true,
		},
		{
			Data: &License{},
			Key: crypto.Signer(&CryptoSigner{
				PublicKey: &dsa.PublicKey{},
			}),
			ShouldFail: true,
		},
		{
			Data: &License{},
			Key: &CryptoSigner{
				PublicKey: signKey.PublicKey,
				SignFunc: func(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
					return nil, errors.New("Fail")
				},
			},
			ShouldFail: true,
		},
		{
			Data:       &License{},
			Key:        signKey,
			ShouldFail: false,
		},
		{
			Data: &License{
				MinVersion: 1,
				MaxVersion: 2,
				Features: []Feature{
					{
						Oid:   oidLicenseMinVersion,
						Limit: 5,
					},
				},
			},
			Key:        signKey,
			ShouldFail: false,
		},
	}

	for _, test := range tests {
		_, err := CreateLicense(test.Data, test.Key)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestLoadLicenseWithCustomer(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	encoded := &License{
		SerialNumber: testLicenseSerial,
		ValidFrom:    time.Unix(testLicenseValidFrom, 0),
		ValidUntil:   time.Unix(testLicenseValidUntil, 0),
		Customer: Customer{
			Name:         testLicenseCustomerName,
			City:         testLicenseCustomerCity,
			Organization: testLicenseCustomerOrganization,
		},
	}
	data, err := CreateLicense(encoded, privateEcc)
	assert.NoError(t, err)

	decoder, err := Load(data, privateEcc.Public(), nil)
	assert.NoError(t, err)

	assert.Equalf(t, encoded.SerialNumber, decoder.SerialNumber, "Invalid Serial")

	assert.Equalf(t, encoded.Customer.Name, decoder.Customer.Name, "Invalid Customer")
	assert.Equalf(t, encoded.Customer.City, decoder.Customer.City, "Invalid customer City")
	assert.Equalf(t, encoded.Customer.Country, decoder.Customer.Country, "Invalid customer Country")
	assert.Equalf(t, encoded.Customer.Organization, decoder.Customer.Organization, "Invalid customer Organization")
	assert.Equalf(t, encoded.Customer.OrganizationalUnit, decoder.Customer.OrganizationalUnit, "Invalid customer OrganizationalUnit")

	encoded = &License{
		Customer: Customer{
			City:               testLicenseCustomerCity,
			Country:            testLicenseCustomerCountry,
			OrganizationalUnit: testLicenseCustomerOrganizationalUnit,
		},
	}

	data, err = CreateLicense(encoded, privateEcc)
	assert.NoError(t, err)

	decoder, err = Load(data, privateEcc.Public(), nil)
	assert.NoError(t, err)

	assert.Equalf(t, encoded.Customer.Name, decoder.Customer.Name, "Invalid Customer")
	assert.Equalf(t, encoded.Customer.City, decoder.Customer.City, "Invalid customer City")
	assert.Equalf(t, encoded.Customer.Country, decoder.Customer.Country, "Invalid customer Country")
	assert.Equalf(t, encoded.Customer.Organization, decoder.Customer.Organization, "Invalid customer Organization")
	assert.Equalf(t, encoded.Customer.OrganizationalUnit, decoder.Customer.OrganizationalUnit, "Invalid customer OrganizationalUnit")
}

func TestLoadLicenseWithWrongAuthority(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	testLicense1, err := CreateLicense(&License{
		ProductName:  testLicenseProduct,
		SerialNumber: testLicenseSerial,
	}, privateEcc)
	assert.NoError(t, err)

	// Random Authority
	privateEcc, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Parse
	_, err = Load(testLicense1, privateEcc.Public(), nil)
	assert.Error(t, err)

}

func TestLoadLicenseWithExpire(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	encoded := &License{
		ProductName: testLicenseProduct,
		ValidUntil:  time.Unix(1575158400, 0),
	}

	data, err := CreateLicense(encoded, privateEcc)
	assert.NoError(t, err)

	decoded, err := Load(data, privateEcc.Public(), nil)
	assert.NoError(t, err)

	assert.Equalf(t, encoded.ValidFrom, decoded.ValidFrom, "Invalid min version")
	assert.Equalf(t, encoded.ValidUntil, decoded.ValidUntil, "Invalid max version")

	encoded = &License{
		ValidFrom: time.Unix(1575158400, 0),
	}

	data, err = CreateLicense(encoded, privateEcc)
	assert.NoError(t, err)

	decoded, err = Load(data, privateEcc.Public(), nil)
	assert.NoError(t, err)

	assert.Equalf(t, encoded.ValidFrom, decoded.ValidFrom, "Invalid min version")
	assert.Equalf(t, encoded.ValidUntil, decoded.ValidUntil, "Invalid max version")
}

func TestLoadLicenseWithVersion(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	testLicense, err := CreateLicense(&License{
		ProductName:  testLicenseProduct,
		SerialNumber: testLicenseSerial,
		MinVersion:   testLicenseMinVersion,
		MaxVersion:   testLicenseMaxVersion,
	}, privateEcc)
	assert.NoError(t, err)

	license, err := Load(testLicense, privateEcc.Public(), nil)
	assert.NoError(t, err)

	assert.Equalf(t, Version(testLicenseMinVersion), license.MinVersion, "Invalid min version")
	assert.Equalf(t, Version(testLicenseMaxVersion), license.MaxVersion, "Invalid max version")
}

func TestLoadLicenseWithSerial(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	genLicense := &License{
		ProductName:  testLicenseProduct,
		SerialNumber: testLicenseSerial,
		ValidFrom:    time.Unix(testLicenseValidFrom, 0),
		ValidUntil:   time.Unix(testLicenseValidUntil, 0),
		Customer: Customer{
			Name: testLicenseCustomerName,
		},
	}
	// Valid SN
	testLicense1, err := CreateLicense(genLicense, privateEcc)
	assert.NoError(t, err)

	genLicense.SerialNumber = "Invalid Serial Number"
	testLicense2, err := CreateLicense(genLicense, privateEcc)
	assert.NoError(t, err)

	validator := func(produc, sn string, v, x, y, z int64) error {
		if sn == testLicenseSerial {
			return nil
		}
		return errors.New("Invalid Serial")
	}
	// TestValid SN
	_, err = Load(testLicense1, privateEcc.Public(), validator)
	assert.NoError(t, err)

	// TestInvalid SN
	_, err = Load(testLicense2, privateEcc.Public(), validator)
	assert.Error(t, err)
}

func TestLoadLicenseCorrupt(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	genLicense := &License{
		ProductName:  testLicenseProduct,
		SerialNumber: testLicenseSerial,
	}
	testLicense, err := CreateLicense(genLicense, privateEcc)
	assert.NoError(t, err)

	// Corrupted data
	corrupteLicense := append(testLicense[3:], testLicense[:3]...)

	prependLicense := append(testLicense, testLicense[:10]...)

	_, err = Load(corrupteLicense, privateEcc.Public(), nil)
	assert.Error(t, err)

	_, err = Load(prependLicense, privateEcc.Public(), nil)
	assert.Error(t, err)
}

func TestLoadLicenseInvalidKey(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	testLicense, err := CreateLicense(&License{
		ProductName:  testLicenseProduct,
		SerialNumber: testLicenseSerial,
	}, privateEcc)
	assert.NoError(t, err)

	dsaKey := &CryptoSigner{
		PublicKey: &dsa.PublicKey{},
	}

	// Parse
	_, err = Load(testLicense, dsaKey, nil)
	assert.Error(t, err)
}

func TestLoadLicenseInvalidAlorithm(t *testing.T) {
	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	licObject := asnLicense{
		License: asnSignedLicense{
			SignatureAlgorithm: oidLicenseMinVersion,
		},
		Signature: asnSignature{
			AlgorithmIdentifier: oidLicenseMinVersion,
		},
	}

	testLicense, err := asn1.Marshal(licObject)
	assert.NoError(t, err)

	// Parse
	_, err = Load(testLicense, privateEcc, nil)
	assert.Error(t, err)
}
