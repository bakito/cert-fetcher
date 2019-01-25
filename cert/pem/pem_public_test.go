package pem_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bakito/cert-fetcher/cert/pem"
	"github.com/stretchr/testify/assert"
)

func Test_Export(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	outFile := "test-cert.pem"
	err := pem.Export(ts.URL, []int{0}, outFile)
	assert.NoError(t, err)
}
