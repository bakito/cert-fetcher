package pem

import (
	"crypto/x509"
	"testing"

	"github.com/bakito/cert-fetcher/cert/test"
	"github.com/stretchr/testify/assert"
)

func Test_exportCerts_min(t *testing.T) {
	_, cnt, err := exportCerts([]*x509.Certificate{test.NewCert(t)}, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, cnt)
}

func Test_exportCerts_cert_0_with_name(t *testing.T) {
	_, cnt, err := exportCerts([]*x509.Certificate{test.NewCert(t)}, []int{0})
	assert.NoError(t, err)
	assert.Equal(t, 1, cnt)
}

func Test_exportCerts_cert_1(t *testing.T) {
	_, cnt, err := exportCerts([]*x509.Certificate{test.NewCert(t)}, []int{1})
	assert.NoError(t, err)
	assert.Equal(t, 0, cnt)
}
