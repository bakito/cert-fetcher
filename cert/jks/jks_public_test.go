package jks_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bakito/cert-fetcher/cert/jks"
)

func Test_Export(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
	}))
	defer ts.Close()

	outFile := "test-cert.jks"
	err := jks.Export(ts.URL, []int{0}, "", "changeit", outFile)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
}
