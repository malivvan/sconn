package sconn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"path/filepath"
)

type CertStore struct {
	self    tls.Certificate
	trusted *x509.CertPool
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

func (store *CertStore) TrustFolder(path string) error {
	matches, err := filepath.Glob(path)
	if err != nil {
		return err
	}
	for _, match := range matches {
		err = store.TrustFile(match)
		if err != nil {
			return err
		}
	}
	return nil
}

func (store *CertStore) TrustFile(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	if !store.Trust(b) {
		return errors.New("failed to add certificate to cert store")
	}
	return nil
}

func (store *CertStore) Trust(certPEMBlock []byte) bool {
	return store.trusted.AppendCertsFromPEM(certPEMBlock)
}
