package sconn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

func EnsureClientCertificate(path string, commonName string, validateFrom time.Time, validateFor time.Duration) (string, string, error) {
	return ensureCertificate(path, x509.ExtKeyUsageClientAuth, commonName, []string{}, validateFrom, validateFor)
}

func EnsureServerCertificate(path string, commonName string, addresses []string, validateFrom time.Time, validateFor time.Duration) (string, string, error) {
	return ensureCertificate(path, x509.ExtKeyUsageServerAuth, commonName, addresses, validateFrom, validateFor)
}

func GenerateClientCertificate(commonName string, validateFrom time.Time, validateFor time.Duration) ([]byte, []byte, error) {
	return generateCertificate(x509.ExtKeyUsageClientAuth, commonName, []string{}, validateFrom, validateFor)
}

func GenerateServerCertificate(commonName string, addresses []string, validateFrom time.Time, validateFor time.Duration) ([]byte, []byte, error) {
	return generateCertificate(x509.ExtKeyUsageServerAuth, commonName, addresses, validateFrom, validateFor)
}

func ensureCertificate(path string, usage x509.ExtKeyUsage, commonName string, addresses []string, validFrom time.Time, validFor time.Duration) (string, string, error) {
	certPath := path + ".pem"
	keyPath := path + "-key.pem"
	if checkCertificate(certPath, keyPath) {
		return certPath, keyPath, nil
	}
	certBytes, keyBytes, err := generateCertificate(usage, commonName, addresses, validFrom, validFor)
	if err != nil {
		return "", "", err
	}
	err = ioutil.WriteFile(certPath, certBytes, 0600)
	if err != nil {
		return "", "", err
	}
	err = ioutil.WriteFile(keyPath, keyBytes, 0600)
	if err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func generateCertificate(usage x509.ExtKeyUsage, commonName string, addresses []string, validFrom time.Time, validFor time.Duration) ([]byte, []byte, error) {

	// generate random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	// generate keypair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// create x509 template
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}

	// add addresses to the template
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, address)
		}
	}

	// self sign certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, err
	}

	// marshal certificate
	var certBuf bytes.Buffer
	pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certBytes := certBuf.Bytes()

	// marshal private key
	var keyBuf bytes.Buffer
	pkcs8PrivateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(&keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8PrivateKeyBytes})
	keyBytes := keyBuf.Bytes()

	return certBytes, keyBytes, nil
}

func checkCertificate(certPath, keyPath string) bool {
	certBytes, certErr := ioutil.ReadFile(certPath)
	if certErr != nil {
		return false
	}
	keyBytes, keyErr := ioutil.ReadFile(keyPath)
	if keyErr != nil {
		return false
	}
	_, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return false
	}
	return true
}
