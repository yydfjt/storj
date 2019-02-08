// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package peertls

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"io"

	"github.com/spacemonkeygo/openssl"
	"github.com/zeebo/errs"

	"storj.io/storj/pkg/pkcrypto"
	"storj.io/storj/pkg/utils"
)

var (
	// ErrNotExist is used when a file or directory doesn't exist.
	ErrNotExist = errs.Class("file or directory not found error")
	// ErrGenerate is used when an error occurred during cert/key generation.
	ErrGenerate = errs.Class("tls generation error")
	// ErrTLSTemplate is used when an error occurs during tls template generation.
	ErrTLSTemplate = errs.Class("tls template error")
	// ErrVerifyPeerCert is used when an error occurs during `VerifyPeerCertificate`.
	ErrVerifyPeerCert = errs.Class("tls peer certificate verification error")
	// ErrVerifyCertificateChain is used when a certificate chain can't be verified from leaf to root
	// (i.e.: each cert in the chain should be signed by the preceding cert and the root should be self-signed).
	ErrVerifyCertificateChain = errs.Class("certificate chain signature verification failed")
	// ErrVerifyCAWhitelist is used when a signature wasn't produced by any CA in the whitelist.
	ErrVerifyCAWhitelist = errs.Class("not signed by any CA in the whitelist")
)

// PeerCertVerificationFunc is the signature for an `openssl.Ctx`'s
// `VerifyCallback` function.
type PeerCertVerificationFunc = openssl.VerifyCallback

// VerifyPeerFunc combines multiple `openssl.VerifyCallback`
// functions and adds certificate parsing.
func VerifyPeerFunc(next ...PeerCertVerificationFunc) PeerCertVerificationFunc {
	return func(preverify_ok bool, store *openssl.CertificateStoreCtx) bool {
		currentCert := store.GetCurrentCert()
		for _, n := range next {
			if n != nil {
				if ok := n(preverify_ok, store); !ok {
					return false
				}
			}
		}
		return true
	}
}

// VerifyPeerCertChains verifies that the certificate chain contains certificates
// which are signed by their respective parents, ending with a self-signed root.
func VerifyPeerCertChains(_ bool, store *openssl.CertificateStoreCtx) bool {
	// XXX
	return true
}

// VerifyCAWhitelist verifies that the peer identity's CA was signed by any one
// of the (certificate authority) certificates in the provided whitelist.
func VerifyCAWhitelist(cas []*openssl.Certificate) PeerCertVerificationFunc {
	if cas == nil {
		return nil
	}
	return func(_ bool, store *openssl.CertificateStoreCtx) bool {
		// XXX
		return true
		//for _, ca := range cas {
		//	err := verifyCertSignature(ca, parsedChains[0][CAIndex])
		//	if err == nil {
		//		return nil
		//	}
		//}
		//return ErrVerifyCAWhitelist.New("CA cert")
	}
}

// TLSContext creates an openssl.Ctx from chains, key and leaf.
func TLSContext(chain [][]byte, leaf *openssl.Certificate, key openssl.PrivateKey) (*openssl.Ctx, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if leaf == nil {
		leaf, err = pkcrypto.CertFromDER(chain[0])
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.UseCertificate(leaf); err != nil {
		return nil, errs.Wrap(err)
	}
	for i, certBytes := range chain {
		cert, err := openssl.LoadCertificateFromPEM(certBytes)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		if err := ctx.AddChainCertificate(cert); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	if err := ctx.UsePrivateKey(key); err != nil {
		return nil, errs.Wrap(err)
	}
	return ctx, nil
}

// WriteChain writes the certificate chain (leaf-first) to the writer, PEM-encoded.
func WriteChain(w io.Writer, chain ...*pkcrypto.CertWithExtensions) error {
	if len(chain) < 1 {
		return errs.New("expected at least one certificate for writing")
	}

	var extErrs utils.ErrorGroup
	for _, c := range chain {
		if err := pkcrypto.WriteCertPEM(w, c.C); err != nil {
			return errs.Wrap(err)
		}

		for _, e := range c.ExtraExtensions {
			if err := pkcrypto.WritePKIXExtensionPEM(w, &e); err != nil {
				extErrs.Add(errs.Wrap(err))
			}
		}
	}
	return extErrs.Finish()
}

// ChainBytes returns bytes of the certificate chain (leaf-first) to the writer, PEM-encoded.
func ChainBytes(chain ...*pkcrypto.CertWithExtensions) ([]byte, error) {
	var data bytes.Buffer
	err := WriteChain(&data, chain...)
	return data.Bytes(), err
}

// CreateSelfSignedCertificate creates a new self-signed X.509v3 certificate
// using fields from the given template.
func CreateSelfSignedCertificate(key openssl.PrivateKey, template *openssl.Certificate) (*openssl.Certificate, error) {
	return CreateCertificate(pkcrypto.PublicKeyFromPrivate(key), key, template, template)
}

// CreateCertificate creates a new X.509v3 certificate based on a template.
// The new certificate:
//
//  * will have the public key given as 'signee'
//  * will be signed by 'signer' (which should be the private key of 'issuer')
//  * will be issued by 'issuer'
//  * will have metadata fields copied from 'template'
//
// Returns the new Certificate object.
func CreateCertificate(signee openssl.PublicKey, signer crypto.PrivateKey, template, issuer *openssl.Certificate) (*openssl.Certificate, error) {
	cb, err := openssl.CreateCertificate(
		rand.Reader,
		template,
		issuer,
		signee,
		signer,
	)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return pkcrypto.CertFromDER(cb)
}
