package pem_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bakito/cert-fetcher/cert/pem"
	"github.com/stretchr/testify/assert"
)

func Test_Export(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	outFile := "test-cert.pem"
	err := pem.ExportTo(ts.URL, []int{0}, outFile)
	assert.NoError(t, err)
	_ = os.Remove("test-cert.pem")
}
