package cert_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/bakito/cert-fetcher/cert"
	"github.com/bakito/cert-fetcher/cert/test"
)

func Test_FetchCertificates_No_TLS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
	}))
	defer ts.Close()

	_, err := cert.FetchCertificates(ts.URL)
	if err == nil {
		t.Error("expected error, but got nil")
	}
}

func Test_FetchCertificates_Chain(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
	}))
	defer ts.Close()
	certs, err := cert.FetchCertificates(ts.URL)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, but got %d", len(certs))
	}
}

func Test_Print(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
	}))
	defer ts.Close()

	out, revert := cert.MockPrintTarget()
	defer revert()

	cert.Print(ts.URL)
	pattern := "Certificate #0\\:\nSubject: .*\nIssuer\\: .*\nNotBefore\\: .*\nNotAfter\\: .*\n\n"
	matched, err := regexp.MatchString(pattern, out.String())
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Errorf("output does not match pattern %q\noutput:\n%s", pattern, out.String())
	}
}

func Test_IsToExport(t *testing.T) {
	if !cert.IsToExport([]int{}, 1) {
		t.Error("expected IsToExport([], 1) to be true")
	}
	if !cert.IsToExport([]int{1}, 1) {
		t.Error("expected IsToExport([1], 1) to be true")
	}
	if cert.IsToExport([]int{1}, 2) {
		t.Error("expected IsToExport([1], 2) to be false")
	}
}

func Test_PrintAdd(t *testing.T) {
	out, revert := cert.MockPrintTarget()
	defer revert()

	cert.PrintAdd(1, test.NewCert(t))

	expected := " + Adding   certificate #1: GeoTrust Global CA\n"
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
}

func Test_PrintSkip(t *testing.T) {
	out, revert := cert.MockPrintTarget()
	defer revert()

	cert.PrintSkip(1, test.NewCert(t))

	expected := " - Skipping certificate #1: GeoTrust Global CA \n"
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
}
