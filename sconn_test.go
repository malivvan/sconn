package sconn

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestAccept(t *testing.T) {

	// prepare certificates
	clientCert, clientKey, err := GenerateClientCertificate("client", time.Now(), 1*time.Hour)
	assert.NoError(t, err)
	serverCert, serverKey, err := GenerateServerCertificate("server", []string{"testing.com"}, time.Now(), 1*time.Hour)
	assert.NoError(t, err)

	// prepare trust stores
	clientStore, err := NewCertStore(clientCert, clientKey)
	assert.NoError(t, err)
	assert.True(t, clientStore.Trust(serverCert))
	serverStore, err := NewCertStore(serverCert, serverKey)
	assert.NoError(t, err)
	assert.True(t, serverStore.Trust(clientCert))

	// create listener
	listener := NewListener("tcp", ":0", serverStore)
	err = listener.Listen(func(conn *tls.Conn, cert *x509.Certificate, err error) {
		b, _ := json.MarshalIndent(cert, "", "  ")
		fmt.Println(string(b))
	})
	assert.NoError(t, err)
	defer listener.Close()

	// create dialer
	clientConn, _, err := Dial("tcp", "testing.com:"+strings.Split(listener.Addr().String(), ":")[3], 5*time.Second, clientStore)
	assert.NoError(t, err)
	time.Sleep(time.Second)
	clientConn.Close()
}
