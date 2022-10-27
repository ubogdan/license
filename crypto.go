package license

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
)

var (
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
}

// Identify Signature Algorithm by oid.
func authorityHashFromAlgorithm(key interface{}, license asnSignedLicense) ([]byte, crypto.Hash, error) {
	var hashFunc crypto.Hash

	digest, err := authorityHashFromKey(key)
	if err != nil {
		return nil, hashFunc, err
	}

	if !bytes.Equal(digest, license.AuthorityKeyID) {
		return nil, hashFunc, errors.New("invalid Authority Id")
	}

	var pubKeyAlgo x509.PublicKeyAlgorithm

	switch key.(type) {
	case *rsa.PublicKey:
		pubKeyAlgo = x509.RSA
	case *ecdsa.PublicKey:
		pubKeyAlgo = x509.ECDSA
	}

	for _, match := range signatureAlgorithmDetails {
		if license.SignatureAlgorithm.Equal(match.oid) && match.pubKeyAlgo == pubKeyAlgo {
			return asnLicenseHash(license, match.hash)
		}
	}

	return nil, hashFunc, errors.New("algorithm unimplemented")
}

func authorityHashFromPublicKey(key interface{}) ([]byte, crypto.Hash, asn1.ObjectIdentifier, error) {
	var (
		signatureAlgorithm asn1.ObjectIdentifier
		hashFunc           crypto.Hash
	)

	digest, err := authorityHashFromKey(key)
	if err != nil {
		return nil, hashFunc, signatureAlgorithm, err
	}

	switch pub := key.(type) {
	case *rsa.PublicKey:
		hashFunc = crypto.SHA256
		signatureAlgorithm = oidSignatureSHA256WithRSA
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			signatureAlgorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			signatureAlgorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			signatureAlgorithm = oidSignatureECDSAWithSHA512
		}
	default:
		return nil, hashFunc, signatureAlgorithm, errors.New("only RSA and ECDSA keys supported")
	}

	return digest, hashFunc, signatureAlgorithm, nil
}

func checkSignature(digest, signature []byte, hashType crypto.Hash, publicKey crypto.PublicKey) (err error) {
	if !hashType.Available() {
		return errors.New("cannot verify signature: algorithm unimplemented")
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, signature)
	case *ecdsa.PublicKey:
		return ecdsaVerifyPCKS(pub, digest, signature)
	}

	return errors.New("cannot verify signature: only RSA and ECDSA keys supported")
}

func ecdsaVerifyPCKS(pub *ecdsa.PublicKey, digest, signature []byte) error {
	type ecdsaSignature struct {
		R, S *big.Int
	}

	ecdsaSig := new(ecdsaSignature)

	rest, err := asn1.Unmarshal(signature, ecdsaSig)
	if err != nil || len(rest) != 0 {
		return errors.New("license: malformed data")
	}

	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 || !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
		return errors.New("license: verification failure")
	}

	return nil
}

func authorityHashFromKey(key interface{}) ([]byte, error) {
	sigBytes, err := x509.MarshalPKIXPublicKey(key) // *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
	if err != nil {
		return nil, err
	}

	digest := sha1.New()

	_, err = digest.Write(sigBytes)
	if err != nil {
		return nil, err
	}

	return digest.Sum(nil), nil
}

func signAsnObject(license asnSignedLicense, key crypto.Signer, hash crypto.Hash) ([]byte, error) {
	digest, _, err := asnLicenseHash(license, hash)
	if err != nil {
		return nil, err
	}

	return key.Sign(rand.Reader, digest, hash)
}

func asnLicenseHash(license asnSignedLicense, h crypto.Hash) (hash []byte, hashFunc crypto.Hash, err error) {
	asnData, err := asn1.Marshal(license)
	if err != nil {
		return nil, h, err
	}

	digest := h.New()

	_, err = digest.Write(asnData)
	if err != nil {
		return nil, h, err
	}

	return digest.Sum(nil), h, nil
}
