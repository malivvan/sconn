package sconn

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Dialer struct {
	network string
	address string
	timeout time.Duration
	store   *CertStore

	wg     sync.WaitGroup
	closed atomic.Value
	conn   net.Conn
}

func NewDialer(network string, address string, timeout time.Duration, store *CertStore) *Dialer {
	d := &Dialer{
		network: network,
		address: address,
		timeout: timeout,
		store:   store,
	}
	d.closed.Store(true)
	return d
}

func (d *Dialer) Dial(handler func(conn *tls.Conn, cert *x509.Certificate, err error)) error {
	if !d.closed.Load().(bool) {
		return errors.New("dialer was already started")
	}
	d.closed.Store(false)

	d.wg.Add(1)
	go func() {
		defer func() {
			d.wg.Done()
		}()
		for !d.closed.Load().(bool) {

			// dial according to configuration
			conn, cert, err := Dial(d.network, d.address, d.timeout, d.store)
			if err != nil {
				handler(nil, nil, err)
				time.Sleep(5* time.Second)
				continue
			}

			// execute handler and cleanup after
			d.conn = conn
			handler(conn, cert, err)
			conn.Close()
		}
	}()

	return nil
}

func (d *Dialer) IsClosed() bool {
	return d.closed.Load().(bool)
}

func (d *Dialer) Close() error {
	d.closed.Store(true)
	var err error
	if d.conn != nil {
		err = d.conn.Close()
	}
	d.wg.Wait()
	return err
}

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















