package sconn

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

type Listener struct {
	network string
	address string
	store   *CertStore

	wg       sync.WaitGroup
	closed   atomic.Value
	listener net.Listener
}

func NewListener(network string, address string, store *CertStore) *Listener {
	l := &Listener{
		network: network,
		address: address,
		store:   store,
	}
	l.closed.Store(true)
	return l
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) Listen(handler func(conn *tls.Conn, cert *x509.Certificate, err error)) error {
	if !l.closed.Load().(bool) {
		return errors.New("listener was already started")
	}

	// create tls config with enabled client auth
	config := tls.Config{
		Certificates: []tls.Certificate{l.store.self},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    l.store.trusted,
		Rand:         rand.Reader,
	}

	// start listening
	var err error
	l.listener, err = tls.Listen(l.network, l.address, &config)
	if err != nil {
		return err
	}
	l.closed.Store(false)

	// dispatcher routine
	l.wg.Add(1)
	go func() {
		defer func() {
			l.wg.Done()
		}()
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				if l.closed.Load().(bool) {
					return // DONE
				}
				handler(nil, nil, err)
				continue
			}

			// get tls connection, force handshake, validate
			tlsConn := conn.(*tls.Conn)
			tlsConn.Handshake()
			state := tlsConn.ConnectionState()
			if state.HandshakeComplete == false {
				tlsConn.Close()
				handler(nil, nil, errors.New("error completing handshake"))
				continue
			}
			if len(state.PeerCertificates) != 1 {
				tlsConn.Close()
				handler(nil, nil, errors.New("peer certificates supplied != 0"))
				continue
			}

			// dispatch
			go handler(tlsConn, state.PeerCertificates[0], nil)
		}
	}()

	return nil
}

// Close Listener.
func (l *Listener) Close() error {
	l.closed.Store(true)
	err := l.listener.Close()
	l.wg.Wait()
	return err
}
