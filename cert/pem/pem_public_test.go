package pem_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bakito/cert-fetcher/cert/pem"
)

func Test_Export(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
	}))
	defer ts.Close()

	outFile := "test-cert.pem"
	err := pem.ExportTo(ts.URL, []int{0}, outFile)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	_ = os.Remove("test-cert.pem")
}
