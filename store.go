package sconn

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"path/filepath"
)

type CertStore struct {
	self    tls.Certificate
	trusted *x509.CertPool
}

func LoadCertStore(certPath, keyPath string) (*CertStore, error) {
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return NewCertStore(certBytes, keyBytes)
}

func NewCertStore(certPEMBlock, keyPEMBlock []byte) (*CertStore, error) {
	var err error
	store := &CertStore{trusted: x509.NewCertPool()}
	store.self, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (store *CertStore) TrustFolder(path string) ([]*x509.Certificate, error) {
	matches, err := filepath.Glob(path)
	if err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{}
	for _, match := range matches {
		cert, err := store.TrustFile(match)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (store *CertStore) TrustFile(path string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return store.Trust(b)
}

func (store *CertStore) Trust(certPEMBlock []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(certPEMBlock)
	if len(rest) != 0 {
		return  nil, errors.New("more than one block in certificate pem file")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate pem file does not contain certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	store.trusted.AddCert(cert)
	return cert, nil
}
