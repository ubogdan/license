package license

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ubogdan/mock"
)

func Test_auhtorityhashFromPublicKey(t *testing.T) {

	rsa1024Key, _ := rsa.GenerateKey(rand.Reader, 1024)
	ell256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ell384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ell521Key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ed25519Key, _, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		Key        crypto.Signer
		Hash       crypto.Hash
		ShouldFail bool
	}{
		{
			Key:        rsa1024Key,
			Hash:       crypto.SHA256,
			ShouldFail: false,
		},
		{
			Key:        ell256Key,
			Hash:       crypto.SHA256,
			ShouldFail: false,
		},
		{
			Key:        ell384Key,
			Hash:       crypto.SHA384,
			ShouldFail: false,
		},
		{
			Key:        ell521Key,
			Hash:       crypto.SHA512,
			ShouldFail: false,
		},

		{
			Key: &mock.CryptoSigner{
				PublicKey: ed25519Key,
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
		_, hash, _, err := auhtorityhashFromPublicKey(pubkey)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, hash, test.Hash)
		}
	}
}

func Test_auhtorityhashFromAlgorithm(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	authorityID, err := authorityHashFromKey(key.Public())
	assert.NoError(t, err)

	tests := []struct {
		License    asnSignedLicense
		Hash       crypto.Hash
		ShouldFail bool
	}{
		{
			License: asnSignedLicense{ // invalid Key for selected algorithm
				AuthorityKeyID:     authorityID,
				SignatureAlgorithm: oidSignatureECDSAWithSHA1,
			},
			ShouldFail: true,
		},
		{
			License: asnSignedLicense{
				AuthorityKeyID:     authorityID,
				SignatureAlgorithm: oidSignatureSHA1WithRSA,
			},
			Hash:       crypto.SHA1,
			ShouldFail: false,
		},
		{
			License: asnSignedLicense{ // invalid/unknown algorithm
				AuthorityKeyID:     authorityID,
				SignatureAlgorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 100},
			},
			ShouldFail: true,
		},
	}

	for _, test := range tests {
		_, hash, err := auhtorityhashFromAlgorithm(key.Public(), test.License)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, hash, test.Hash)
		}
	}
}

type mocHash struct{}

func (m mocHash) Write(p []byte) (n int, err error) { return 0, errors.New("Error") }
func (m mocHash) Reset()                            { return }
func (m mocHash) Size() int                         { return 0 }
func (m mocHash) BlockSize() int                    { return 0 }
func (m mocHash) Sum(b []byte) []byte               { return nil }

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
