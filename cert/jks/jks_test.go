package jks

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

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "", "", "")
	assert.NoError(t, err)
	assert.Equal(t, "java keystore file foo.bar.jks with 1 certificate(s) created.\n", out.String())
	os.Remove("foo.bar.jks")
}

func Test_exportCerts_cert_0_with_name(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", []int{0}, "", "", "file-name.jks")
	assert.NoError(t, err)
	assert.Equal(t, "java keystore file file-name.jks with 1 certificate(s) created.\n", out.String())
	os.Remove("file-name.jks")
}

func Test_exportCerts_cert_1(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", []int{1}, "", "", "")
	assert.NoError(t, err)
	assert.Equal(t, "java keystore file foo.bar.jks with 0 certificate(s) created.\n", out.String())
	os.Remove("foo.bar.jks")
}

func Test_exportCerts_to_existing_empty_jks(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "../../testdata/empty.jks", "changeit", "")
	assert.NoError(t, err)
	assert.Equal(t, `Using existing java keystore ../../testdata/empty.jks to add the new certificates
java keystore file foo.bar.jks with 1 additional certificate(s) created.
`, out.String())
	os.Remove("foo.bar.jks")
}

func Test_exportCerts_to_existing_jks_duplicate(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "../../testdata/geotrust.jks", "changeit", "")
	assert.NoError(t, err)
	assert.Equal(t, `Using existing java keystore ../../testdata/geotrust.jks to add the new certificates
java keystore file foo.bar.jks with 0 additional certificate(s) created.
`, out.String())
	os.Remove("foo.bar.jks")
}

func Test_exportCerts_to_existing_jks_additional(t *testing.T) {

	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "../../testdata/google.jks", "changeit", "")
	assert.NoError(t, err)
	assert.Equal(t, `Using existing java keystore ../../testdata/google.jks to add the new certificates
java keystore file foo.bar.jks with 1 additional certificate(s) created.
`, out.String())
	os.Remove("foo.bar.jks")
}

func mockPrintTarget() (*bytes.Buffer, func()) {
	bak := out
	mock := new(bytes.Buffer)
	out = mock
	return mock, func() {
		out = bak
	}
}
