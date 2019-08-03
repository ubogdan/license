package license

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ubogdan/mock"
)

func Test_hashFromPublicKey(t *testing.T) {

	rsa1024Key, _ := rsa.GenerateKey(rand.Reader, 1024)
	ell256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ell384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ell521Key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	tests := []struct {
		Key        crypto.Signer
		ShouldFail bool
	}{
		{
			Key:        rsa1024Key,
			ShouldFail: false,
		},
		{
			Key:        ell256Key,
			ShouldFail: false,
		},
		{
			Key:        ell384Key,
			ShouldFail: false,
		},
		{
			Key:        ell521Key,
			ShouldFail: false,
		},
		{
			Key: &mock.CryptoSigner{
				PublicKey: &ecdsa.PublicKey{},
			},
			ShouldFail: true,
		},
		{
			Key: &mock.CryptoSigner{
				PublicKey: &dsa.PublicKey{},
			},
			ShouldFail: true,
		},
	}

	for _, test := range tests {
		pubkey := test.Key.Public()
		_, _, err := hashFromPublicKey(pubkey)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func Test_hashFuncFromAlgorithm(t *testing.T) {
	tests := []struct {
		Oid        asn1.ObjectIdentifier
		ShouldFail bool
	}{
		{
			Oid:        oidSignatureECDSAWithSHA1,
			ShouldFail: false,
		},
		{
			Oid:        oidSignatureSHA1WithRSA,
			ShouldFail: false,
		},
		{
			Oid:        oidLicenseMinVersion,
			ShouldFail: true,
		},
		{
			Oid:        oidLicenseMaxVersion,
			ShouldFail: true,
		},
	}

	for _, test := range tests {
		_, err := hashFuncFromAlgorithm(test.Oid)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func Test_publicKeySignature(t *testing.T) {
	var err error

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, err = publicKeySignature(rsaKey.Public())
	assert.NoError(t, err)

	_, err = publicKeySignature(rsaKey)
	assert.Error(t, err)
}

func Test_asnObjectSignature(t *testing.T) {
	tests := []struct {
		Data       interface{}
		Hash       hash.Hash
		ShouldFail bool
	}{
		{
			Data: asnSignedLicense{
				SignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: oidSignatureECDSAWithSHA256,
				},
			},
			Hash:       sha1.New(),
			ShouldFail: false,
		},

		{
			Data:       asnSignedLicense{},
			Hash:       sha1.New(),
			ShouldFail: true,
		},
	}

	for _, test := range tests {
		_, err := asnObjectSignature(test.Data, test.Hash)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
