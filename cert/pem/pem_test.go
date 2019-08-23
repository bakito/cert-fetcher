package pem

import (
	"bytes"
	"crypto/x509"
	"os"
	"testing"

	"github.com/bakito/cert-fetcher/cert/test"
	"github.com/stretchr/testify/assert"
)

func Test_exportCerts_min(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "")
	assert.NoError(t, err)
	assert.Equal(t, "pem file foo.bar.pem with 1 certificate(s) created.\n", out.String())
	os.Remove("foo.bar.pem")
}

func Test_exportCerts_cert_0_with_name(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", []int{0}, "file-name.pem")
	assert.NoError(t, err)
	assert.Equal(t, "pem file file-name.pem with 1 certificate(s) created.\n", out.String())
	os.Remove("file-name.pem")
}

func Test_exportCerts_cert_1(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", []int{1}, "")
	assert.NoError(t, err)
	assert.Equal(t, "pem file foo.bar.pem with 0 certificate(s) created.\n", out.String())
	os.Remove("foo.bar.pem")
}

func mockPrintTarget() (*bytes.Buffer, func()) {
	bak := out
	mock := new(bytes.Buffer)
	out = mock
	return mock, func() {
		out = bak
	}
}
