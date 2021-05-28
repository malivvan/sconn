package vssl

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGenerateCertificate(t *testing.T) {
	_, _, err := GenerateClientCertificate("hello world!", time.Now(), 1*time.Hour)
	assert.NoError(t, err)
}
