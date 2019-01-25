package cert_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bakito/cert-fetcher/cert"
	"github.com/bakito/cert-fetcher/cert/test"
	"github.com/stretchr/testify/assert"
)

func Test_FetchCertificates_No_TLS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	_, err := cert.FetchCertificates(ts.URL)
	assert.Error(t, err)
}

func Test_FetchCertificates_Chain(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()
	certs, err := cert.FetchCertificates(ts.URL)
	assert.NoError(t, err)
	assert.Len(t, certs, 1)
}

func Test_Print(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	out, revert := cert.MockPrintTarget()
	defer revert()

	cert.Print(ts.URL)
	assert.Regexp(t, "Certificate #0\\:\nSubject: .*\nIssuer\\: .*\nNotBefore\\: .*\nNotAfter\\: .*\n\n", out.String())
}

func Test_IsToExport(t *testing.T) {
	assert.True(t, cert.IsToExport([]int{}, 1))
	assert.True(t, cert.IsToExport([]int{1}, 1))
	assert.False(t, cert.IsToExport([]int{1}, 2))
}

func Test_PrintAdd(t *testing.T) {
	out, revert := cert.MockPrintTarget()
	defer revert()

	cert.PrintAdd(1, test.NewCert(t))

	assert.Equal(t, " + Adding   certificate #1: GeoTrust Global CA\n", out.String())
}

func Test_PrintSkip(t *testing.T) {
	out, revert := cert.MockPrintTarget()
	defer revert()

	cert.PrintSkip(1, test.NewCert(t))

	assert.Equal(t, " - Skipping certificate #1: GeoTrust Global CA \n", out.String())
}
