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
	"github.com/stretchr/testify/assert"
	"github.com/ubogdan/mock"
	"io"
	"testing"
	"time"
)

const (
	testEccPrivate                        = "MHcCAQEEIMVSIK6PTSva0pJifUoFWU5vNUtsZRAL76nxIA2GT/CroAoGCCqGSM49AwEHoUQDQgAEPG9ZZcLgHiAWGLKScyJnnEzX6gCqTVIc1CQTf77LgxHTc1mkDKh8xJ7VQUh+6od0h9ce5xrHcnJ0VB3rvBVWMQ=="
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

	/*
	   License{
	   		ProductName:  testLicenseProduct,
	   		SerialNumber: testLicenseSerial,
	   		ValidFrom:    time.Unix(testLicenseValidFrom,0),
	   		ValidUntil:   time.Unix(testLicenseValidUntil,0),
	   		Customer: Customer{
	   			Name:               testLicenseCustomerName,
	   		},
	   		Features: []Feature{
	   			{
	   				Oid:        asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 1},
	   				Limit: 1,
	   			},
	   			{
	   				Oid:        asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 2},
	   				Limit: 10,
	   			},
	   			{
	   				Oid:        asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 3},
	   			},
	   		},
	   	}
	*/
	//testLicense1pem = "MIIBCjCBrhMMVGVzdCBQcm9kdWN0Ex0wNTcxNy00M0Q4Ni04MUMwOC1ENjEzMC1GMDkwQzAPEw1UZXN0IEN1c3RvbWVyMCYXETE5MDEwMTAyMDAwMCswMjAwFxExOTEyMzAwMjAwMDArMDIwMDAkMAsGBisGAQMCAQIBATALBgYrBgEDAgICAQowCAYGKwYBAwIDBBRkW6+UMR6rypJQW0vY02eRmKMhrjAKBggqhkjOPQQDAjBXMAoGCCqGSM49BAMCA0kAMEYCIQDs7mH2DoRKrLd5ZjUg87Ms/KPEE+E7pfeTVxDz0ur6mAIhAItLQnfNKdMCAJpxjqbdV8nCEeBGjYP0/jXaYJtIOkqs"

	/*
		License{
			ProductName:  testLicenseProduct,
			SerialNumber: testLicenseSerial,
			ValidFrom:    time.Unix(testLicenseValidFrom, 0),
			ValidUntil:   time.Unix(testLicenseValidUntil, 0),
			MinVersion: testLicenseMinVersion,
			MaxVersion: testLicenseMaxVersion,
			Customer: Customer{
				Name: testLicenseCustomerName,
				City: testLicenseCustomerCity,
				Country:testLicenseCustomerCountry,
				Organization:testLicenseCustomerOrganization,
				OrganizationalUnit:testLicenseCustomerOrganizationalUnit,
			},
			Features: []Feature{
				{
					Oid:   asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 1},
					Limit: 1,
				},
				{
					Oid:   asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 2},
				},
			},
		}
	*/
	//testLicense2pem = "MIIBQTCB5hMMVGVzdCBQcm9kdWN0Ex0wNTcxNy00M0Q4Ni04MUMwOC1ENjEzMC1GMDkwQzA5Ew1UZXN0IEN1c3RvbWVyEwJVUxMITmV3IFlvcmsTCFRFU1QgTExDExBTYWxlcyBEZXBhcnRtZW50MCYXETE5MDEwMTAyMDAwMCswMjAwFxExOTEyMzAwMjAwMDArMDIwMDAyMAsGBisGAQMBAQIBZDAMBgYrBgEDAQICAgPoMAsGBisGAQMCAQIBATAIBgYrBgEDAgIEFGRbr5QxHqvKklBbS9jTZ5GYoyGuMAoGCCqGSM49BAMCMFYwCgYIKoZIzj0EAwIDSAAwRQIhAM3veaQ7Tut6RTKtvFRkw4Tdw2JjBhVA0oHe3WLZgO0+AiAcGxXdRqsrDYTzU4T7iQbiciKMGpaHPvyIYhndlBkY0A=="
)

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
			Key: crypto.Signer(&mock.CryptoSigner{
				PublicKey: &dsa.PublicKey{},
			}),
			ShouldFail: true,
		},
		{
			Data: &License{},
			Key: &mock.CryptoSigner{
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

	decoder := &License{}
	err = decoder.Load(data, privateEcc.Public())
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

	decoder = &License{}
	err = decoder.Load(data, privateEcc.Public())
	assert.NoError(t, err)

	assert.Equalf(t, encoded.Customer.Name, decoder.Customer.Name, "Invalid Customer")
	assert.Equalf(t, encoded.Customer.City, decoder.Customer.City, "Invalid customer City")
	assert.Equalf(t, encoded.Customer.Country, decoder.Customer.Country, "Invalid customer Country")
	assert.Equalf(t, encoded.Customer.Organization, decoder.Customer.Organization, "Invalid customer Organization")
	assert.Equalf(t, encoded.Customer.OrganizationalUnit, decoder.Customer.OrganizationalUnit, "Invalid customer OrganizationalUnit")

}

func TestLoadLicenseWithFeatures(t *testing.T) {

	derBytes, err := base64.StdEncoding.DecodeString(testEccPrivate)
	assert.NoError(t, err)

	privateEcc, err := x509.ParseECPrivateKey(derBytes)
	assert.NoError(t, err)

	testLicense1, err := CreateLicense(&License{
		ProductName:  testLicenseProduct,
		SerialNumber: testLicenseSerial,
		ValidFrom:    time.Unix(testLicenseValidFrom, 0),
		ValidUntil:   time.Unix(testLicenseValidUntil, 0),
		Customer: Customer{
			Name: testLicenseCustomerName,
		},
		Features: []Feature{
			{
				Oid:   asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 1},
				Limit: 1,
			},
			{
				Oid:   asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 2},
				Limit: 10,
			},
			{
				Oid: asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 3},
			},
		},
	}, privateEcc)
	assert.NoError(t, err)

	license := &License{}

	// Register Features
	feat1name := "Feature1"
	feat1oid := asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 1}
	err = license.RegisterFeature(feat1name, feat1oid)
	assert.NoError(t, err)

	feat2name := "Feature2"
	feat2oid := asn1.ObjectIdentifier{1, 3, 6, 1, 3, 2, 2}
	err = license.RegisterFeature(feat2name, feat2oid)
	assert.NoError(t, err)

	// Parse
	err = license.Load(testLicense1, privateEcc.Public())
	assert.NoError(t, err)

	assert.Equalf(t, testLicenseProduct, license.ProductName, "Invalid product")

	assert.Equalf(t, testLicenseSerial, license.SerialNumber, "Invalid serial")

	assert.Equalf(t, time.Unix(testLicenseValidFrom, 0), license.ValidFrom, "Invalid From interval")

	assert.Equalf(t, time.Unix(testLicenseValidUntil, 0), license.ValidUntil, "Invalid Until interval")

	assert.Equalf(t, testLicenseCustomerName, license.Customer.Name, "Invalid customer")

	name, _, limit, err := license.GetFeature(feat1oid)
	assert.NoError(t, err)
	assert.Equalf(t, feat1name, name, "Feature name is Feature1")
	assert.Equalf(t, int64(1), limit, "Feature is limited to 1")

	name, _, limit, err = license.GetFeature(feat2oid)
	assert.NoError(t, err)
	assert.Equalf(t, feat2name, name, "Feature name is Feature2")
	assert.Equalf(t, int64(10), limit, "Feature is limited to 10")

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

	license := &License{}

	// Random Authority
	privateEcc, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Parse
	err = license.Load(testLicense1, privateEcc.Public())
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

	decoded := &License{}
	err = decoded.Load(data, privateEcc.Public())
	assert.NoError(t, err)

	assert.Equalf(t, encoded.ValidFrom, decoded.ValidFrom, "Invalid min version")
	assert.Equalf(t, encoded.ValidUntil, decoded.ValidUntil, "Invalid max version")

	encoded = &License{
		ValidFrom: time.Unix(1575158400, 0),
	}

	data, err = CreateLicense(encoded, privateEcc)
	assert.NoError(t, err)

	err = decoded.Load(data, privateEcc.Public())
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

	license := &License{}
	err = license.Load(testLicense, privateEcc.Public())
	assert.NoError(t, err)

	assert.Equalf(t, int64(testLicenseMinVersion), license.MinVersion, "Invalid min version")
	assert.Equalf(t, int64(testLicenseMaxVersion), license.MaxVersion, "Invalid max version")

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

	license := &License{
		SerialNumberValidator: func(produc, sn string) error {
			if sn == testLicenseSerial {
				return nil
			}
			return errors.New("Invalid Serial")
		},
	}

	// TestValid SN
	err = license.Load(testLicense1, privateEcc.Public())
	assert.NoError(t, err)

	// TestInvalid SN
	err = license.Load(testLicense2, privateEcc.Public())
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

	license := &License{}

	err = license.Load(corrupteLicense, privateEcc.Public())
	assert.Error(t, err)

	err = license.Load(prependLicense, privateEcc.Public())
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

	license := &License{}

	dsaKey := &mock.CryptoSigner{
		PublicKey: &dsa.PublicKey{},
	}

	// Parse
	err = license.Load(testLicense, dsaKey)
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

	license := &License{}

	// Parse
	err = license.Load(testLicense, privateEcc)
	assert.Error(t, err)

}
