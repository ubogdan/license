package license

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"io"
	"testing"
)

func TestCreateLicenseNoProduct(t *testing.T) {
	l := &License{}
	_, err := CreateLicense(l, nil)
	assert.Error(t, err)

}

type elPkMock struct{}

func (e *elPkMock) Public() crypto.PublicKey {

	return &ecdsa.PublicKey{}
}

func (e *elPkMock) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestCreateLicenseWithKeys(t *testing.T) {

	rsa1024Key, _ := rsa.GenerateKey(rand.Reader, 1024)
	ell256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ell384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ell521Key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, ed25519Key, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		Key        crypto.Signer
		ShouldFail bool
	}{
		{
			Key:        nil,
			ShouldFail: true,
		},
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
			Key:        crypto.Signer(&elPkMock{}),
			ShouldFail: true,
		},
		{
			Key:        ed25519Key,
			ShouldFail: true,
		},
	}

	// See https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
	template := &License{
		ProductName: "",
	}

	for _, test := range tests {
		_, err := CreateLicense(template, test.Key)
		if test.ShouldFail {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
