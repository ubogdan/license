package license

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
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
		_, _, _, err := auhtorityhashFromPublicKey(pubkey)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

/*
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
	}

	for _, test := range tests {
		_, err := auhtorityhashFromAlgorithm(nil,test.Oid)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
*/

func Test_publicKeySignature(t *testing.T) {
	var err error

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, err = publicKeySignature(rsaKey.Public())
	assert.NoError(t, err)

	_, err = publicKeySignature(rsaKey)
	assert.Error(t, err)
}

type mocHash struct{}

func (m mocHash) Write(p []byte) (n int, err error) { return 0, errors.New("Error") }
func (m mocHash) Reset()                            { return }
func (m mocHash) Size() int                         { return 0 }
func (m mocHash) BlockSize() int                    { return 0 }
func (m mocHash) Sum(b []byte) []byte               { return nil }

func Test_asnObjectSignature(t *testing.T) {
	tests := []struct {
		Data       interface{}
		Hash       hash.Hash
		ShouldFail bool
	}{
		{
			Data: asnSignedLicense{
				SignatureAlgorithm: oidSignatureECDSAWithSHA256,
			},
			Hash:       sha1.New(),
			ShouldFail: false,
		},
		{
			Data:       asnSignedLicense{},
			Hash:       sha1.New(),
			ShouldFail: true,
		},
		{
			Data: asnSignedLicense{
				SignatureAlgorithm: oidSignatureECDSAWithSHA256,
			},
			Hash:       mocHash{},
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

func Test_checkSignature(t *testing.T) {
	var err error

	hashType := crypto.SHA1

	h := hashType.New()
	h.Write([]byte("Test Message"))
	digest := h.Sum(nil)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)

	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	rsaSignature, err := rsaKey.Sign(rand.Reader, digest, hashType)
	assert.NoError(t, err)

	eccSignature, err := eccKey.Sign(rand.Reader, digest, hashType)
	assert.NoError(t, err)

	err = checkSignature(digest, rsaSignature, crypto.SHA3_512, rsaKey.Public())
	assert.Error(t, err)

	type ecdsaSignature struct {
		R, S *big.Int
	}

	invalidecdsaSignature, err := asn1.Marshal(ecdsaSignature{R: big.NewInt(0), S: big.NewInt(-1)})
	assert.NoError(t, err)

	invalidecdsaSignatureValues, err := asn1.Marshal(ecdsaSignature{R: big.NewInt(123123123123123), S: big.NewInt(543241234123)})
	assert.NoError(t, err)

	tests := []struct {
		Key        crypto.Signer
		Signature  []byte
		ShouldFail bool
	}{
		{
			Key:        rsaKey,
			Signature:  rsaSignature,
			ShouldFail: false,
		},
		{
			Key:        eccKey,
			Signature:  eccSignature,
			ShouldFail: false,
		},
		{
			Key:        eccKey,
			Signature:  []byte{},
			ShouldFail: true,
		},
		{
			Key:        eccKey,
			Signature:  append(eccSignature, []byte{0x00, 0x00, 0x00}...),
			ShouldFail: true,
		},
		{
			Key:        eccKey,
			Signature:  invalidecdsaSignature,
			ShouldFail: true,
		},
		{
			Key:        eccKey,
			Signature:  invalidecdsaSignatureValues,
			ShouldFail: true,
		},
		{
			Key: mock.CryptoSigner{
				PublicKey: &dsa.PublicKey{},
			},
			Signature:  []byte{},
			ShouldFail: true,
		},
	}

	for _, test := range tests {
		err = checkSignature(digest, test.Signature, hashType, test.Key.Public())
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}

}
