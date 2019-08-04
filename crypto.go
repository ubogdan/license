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
	"hash"
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

	ErrUnsupportedAlgorithm = errors.New("license: cannot verify signature: algorithm unimplemented")
	ErrUnsupportedKey       = errors.New("license: only RSA and ECDSA keys supported")
	ErrUnsupportedElliptic  = errors.New("license: unknown elliptic curve")
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

func hashFromPublicKey(key interface{}) (crypto.Hash, pkix.AlgorithmIdentifier, error) {

	var signatureAlgorithm pkix.AlgorithmIdentifier
	var hashFunc crypto.Hash

	switch pub := key.(type) {
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
			return hashFunc, signatureAlgorithm, ErrUnsupportedElliptic
		}

	default:
		return hashFunc, signatureAlgorithm, ErrUnsupportedKey
	}

	return hashFunc, signatureAlgorithm, nil
}

// Identify Signature Algorithm by oid
func hashFuncFromAlgorithm(alogrihm asn1.ObjectIdentifier) (hashFunc crypto.Hash, err error) {
	for _, match := range signatureAlgorithmDetails {
		if alogrihm.Equal(match.oid) {
			return match.hash, nil
		}
	}
	return hashFunc, ErrUnsupportedAlgorithm
}

// public key digest
func publicKeySignature(publicKey interface{}) ([]byte, error) {
	sigBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	digest := sha1.New()
	digest.Write(sigBytes)

	return digest.Sum(nil), nil
}

func checkSignature(digest, signature []byte, hashType crypto.Hash, publicKey crypto.PublicKey) (err error) {
	type ecdsaSignature struct {
		R, S *big.Int
	}

	if !hashType.Available() {
		return ErrUnsupportedAlgorithm
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, signature)
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("license: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("license: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("license: ECDSA verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}

// calculate hash for object
func asnObjectSignature(data interface{}, hash hash.Hash) ([]byte, error) {
	asnData, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(asnData)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), err
}
