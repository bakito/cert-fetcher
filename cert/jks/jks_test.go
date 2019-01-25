package jks_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bakito/cert-fetcher/cert/jks"
	"github.com/stretchr/testify/assert"
)

func Test_FetchCertificates_Chain(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	outFile := "test-cert"
	err := jks.Export(ts.URL, []int{0}, "", "changeit", outFile)
	assert.NoError(t, err)
}
