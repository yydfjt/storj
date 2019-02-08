// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package pkcrypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"

	"github.com/spacemonkeygo/openssl"
	"github.com/zeebo/errs"

	"storj.io/storj/pkg/utils"
)

// WritePublicKeyPEM writes the public key, in a PEM-enveloped
// PKIX form.
func WritePublicKeyPEM(w io.Writer, key openssl.PublicKey) error {
	keyBytes, err := PublicKeyToPEM(key)
	if err != nil {
		return errs.Wrap(err)
	}
	_, err = w.Write(keyBytes)
	return err
}

// PublicKeyToPEM encodes a public key to a PEM-enveloped PKIX form.
func PublicKeyToPEM(key openssl.PublicKey) ([]byte, error) {
	return key.MarshalPKIXPublicKeyPEM()
}

// PublicKeyToPKIX serializes a public key to a PKIX-encoded form.
func PublicKeyToPKIX(key openssl.PublicKey) ([]byte, error) {
	return key.MarshalPKIXPublicKeyDER()
}

// PublicKeyFromPKIX parses a public key from its PKIX encoding.
func PublicKeyFromPKIX(pkixData []byte) (openssl.PublicKey, error) {
	return openssl.LoadPublicKeyFromDER(pkixData)
}

// PublicKeyFromPEM parses a public key from its PEM-enveloped PKIX
// encoding.
func PublicKeyFromPEM(pemData []byte) (openssl.PublicKey, error) {
	return openssl.LoadPublicKeyFromPEM(pemData)
}

// WritePrivateKeyPEM writes the private key to the writer, in a PEM-enveloped
// PKCS#8 form.
func WritePrivateKeyPEM(w io.Writer, key openssl.PrivateKey) error {
	keyBytes, err := PrivateKeyToPEM(key)
	if err != nil {
		return errs.Wrap(err)
	}
	_, err = w.Write(keyBytes)
	return errs.Wrap(err)
}

// PrivateKeyToPEM serializes a private key to a PEM-enveloped PKCS#8 form.
func PrivateKeyToPEM(key openssl.PrivateKey) ([]byte, error) {
	return key.MarshalPKCS1PrivateKeyPEM()
}

// PrivateKeyToPKCS8 serializes a private key to a PKCS#8-encoded form.
func PrivateKeyToPKCS8(key openssl.PrivateKey) ([]byte, error) {
	return key.MarshalPKCS1PrivateKeyDER()
}

// PrivateKeyFromPKCS8 parses a private key from its PKCS#8 encoding.
func PrivateKeyFromPKCS8(keyBytes []byte) (openssl.PrivateKey, error) {
	return openssl.LoadPrivateKeyFromDER(keyBytes)
}

// PrivateKeyFromPEM parses a private key from its PEM-enveloped PKCS#8
// encoding.
func PrivateKeyFromPEM(keyBytes []byte) (openssl.PrivateKey, error) {
	return openssl.LoadPrivateKeyFromPEM(keyBytes)
}

// WriteCertPEM writes the certificate to the writer, in a PEM-enveloped DER
// encoding.
func WriteCertPEM(w io.Writer, cert *openssl.Certificate) error {
	certBytes, err := CertToPEM(cert)
	if err != nil {
		return errs.Wrap(err)
	}
	_, err = w.Write(certBytes)
	return errs.Wrap(err)
}

// CertToPEM returns the bytes of the certificate, in a PEM-enveloped DER
// encoding.
func CertToPEM(cert *openssl.Certificate) ([]byte, error) {
	return cert.MarshalPEM()
}

// CertToDER returns the bytes of the certificate, in a DER encoding.
func CertToDER(cert *openssl.Certificate) ([]byte, error) {
	return cert.MarshalDER()
}

// CertFromDER parses an X.509 certificate from its DER encoding.
func CertFromDER(certDER []byte) (*openssl.Certificate, error) {
	return openssl.LoadCertificateFromDER(certDER)
}

// CertFromPEM parses an X.509 certificate from its PEM-enveloped DER encoding.
func CertFromPEM(certPEM []byte) (*openssl.Certificate, error) {
	return openssl.LoadCertificateFromPEM(certPEM)
}

// CertsFromDER parses an x509 certificate from each of the given byte
// slices, which should be encoded in DER.
func CertsFromDER(rawCerts [][]byte) ([]*openssl.Certificate, error) {
	certs := make([]*openssl.Certificate, len(rawCerts))
	for i, c := range rawCerts {
		var err error
		certs[i], err = CertFromDER(c)
		if err != nil {
			return nil, ErrParse.New("unable to parse certificate at index %d", i)
		}
	}
	return certs, nil
}

// CertsFromPEM parses a PEM chain from a single byte string (the PEM-enveloped
// certificates should be concatenated). The PEM blocks may include PKIX
// extensions.
func CertsFromPEM(pemBytes []byte) ([]CertWithExtensions, error) {
	var (
		encChain  encodedChain
		blockErrs utils.ErrorGroup
	)
	for {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			break
		}
		switch pemBlock.Type {
		case BlockLabelCertificate:
			encChain.AddCert(pemBlock.Bytes)
		case BlockLabelExtension:
			if err := encChain.AddExtension(pemBlock.Bytes); err != nil {
				blockErrs.Add(err)
			}
		}
	}
	if err := blockErrs.Finish(); err != nil {
		return nil, err
	}

	return encChain.Parse()
}

// CertWithExtensions pairs a certificate with a slice of our custom Extensions
type CertWithExtensions struct {
	C               *openssl.Certificate
	ExtraExtensions []pkix.Extension
}

type encodedChain struct {
	chain      [][]byte
	extensions [][][]byte
}

func (e *encodedChain) AddCert(b []byte) {
	e.chain = append(e.chain, b)
	e.extensions = append(e.extensions, [][]byte{})
}

func (e *encodedChain) AddExtension(b []byte) error {
	chainLen := len(e.chain)
	if chainLen < 1 {
		return ErrChainLength.New("expected: >= 1; actual: %d", chainLen)
	}

	i := chainLen - 1
	e.extensions[i] = append(e.extensions[i], b)
	return nil
}

func (e *encodedChain) Parse() ([]CertWithExtensions, error) {
	chain, err := CertsFromDER(e.chain)
	if err != nil {
		return nil, err
	}
	extCerts := make([]CertWithExtensions, len(chain))

	var extErrs utils.ErrorGroup
	for i, cert := range chain {
		extCerts[i].C = cert
		for _, ee := range e.extensions[i] {
			ext, err := PKIXExtensionFromASN1(ee)
			if err != nil {
				extErrs.Add(err)
			}
			extCerts[i].ExtraExtensions = append(extCerts[i].ExtraExtensions, *ext)
		}
	}
	if err := extErrs.Finish(); err != nil {
		return nil, err
	}

	return extCerts, nil
}

// WritePKIXExtensionPEM writes the certificate extension to the writer, in a PEM-
// enveloped PKIX form.
func WritePKIXExtensionPEM(w io.Writer, extension *pkix.Extension) error {
	extBytes, err := PKIXExtensionToASN1(extension)
	if err != nil {
		return errs.Wrap(err)
	}
	err = pem.Encode(w, &pem.Block{Type: BlockLabelExtension, Bytes: extBytes})
	return errs.Wrap(err)
}

// PKIXExtensionToPEM serializes a PKIX certificate extension to PEM-
// enveloped ASN.1 bytes.
func PKIXExtensionToPEM(extension *pkix.Extension) ([]byte, error) {
	asn, err := PKIXExtensionToASN1(extension)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: BlockLabelExtension, Bytes: asn}), nil
}

// PKIXExtensionToASN1 serializes a PKIX certificate extension to the
// appropriate ASN.1 structure for such things. See RFC 5280, section 4.1.1.2.
func PKIXExtensionToASN1(extension *pkix.Extension) ([]byte, error) {
	extBytes, err := asn1.Marshal(extension)
	return extBytes, errs.Wrap(err)
}

// PKIXExtensionFromASN1 deserializes a PKIX certificate extension from
// the appropriate ASN.1 structure for such things.
func PKIXExtensionFromASN1(extData []byte) (*pkix.Extension, error) {
	var extension pkix.Extension
	if _, err := asn1.Unmarshal(extData, &extension); err != nil {
		return nil, ErrParse.New("unable to unmarshal PKIX extension: %v", err)
	}
	return &extension, nil
}

// PKIXExtensionFromPEM parses a PKIX certificate extension from
// PEM-enveloped ASN.1 bytes.
func PKIXExtensionFromPEM(pemBytes []byte) (*pkix.Extension, error) {
	pb, _ := pem.Decode(pemBytes)
	if pb == nil {
		return nil, ErrParse.New("unable to parse PEM block")
	}
	if pb.Type != BlockLabelExtension {
		return nil, ErrParse.New("can not parse PKIX cert extension from PEM block labeled %q", pb.Type)
	}
	return PKIXExtensionFromASN1(pb.Bytes)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func unmarshalECDSASignature(signatureBytes []byte) (r, s *big.Int, err error) {
	var signature ecdsaSignature
	if _, err = asn1.Unmarshal(signatureBytes, &signature); err != nil {
		return nil, nil, err
	}
	return signature.R, signature.S, nil
}
