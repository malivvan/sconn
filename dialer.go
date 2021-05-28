package vssl

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

func Dial(network string, address string, timeout time.Duration, store *CertStore) (*tls.Conn, *x509.Certificate, error) {

	// create client tls configuration
	config := tls.Config{
		Certificates: []tls.Certificate{store.self},
		RootCAs:      store.trusted,
		Rand:         rand.Reader,
	}

	// establish connection
	dialer := new(net.Dialer)
	dialer.Timeout = timeout
	tlsConn, err := tls.DialWithDialer(dialer, network, address, &config)
	if err != nil {
		return nil, nil, err
	}

	// perform handshake and verify connection
	err = tlsConn.Handshake()
	if err != nil {
		tlsConn.Close()
		return nil, nil, errors.New("tls handshake error: " + err.Error())
	}
	state := tlsConn.ConnectionState()
	if state.HandshakeComplete == false {
		tlsConn.Close()
		return nil, nil, errors.New("error completing handshake")
	}
	if len(state.PeerCertificates) != 1 {
		tlsConn.Close()
		return nil, nil, errors.New("peer certificates supplied != 0")
	}

	return tlsConn, state.PeerCertificates[0], nil
}
