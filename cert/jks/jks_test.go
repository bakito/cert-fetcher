package jks

import (
	"bytes"
	"crypto/x509"
	"os"
	"testing"

	"github.com/bakito/cert-fetcher/cert/test"
)

func Test_exportCerts_min(t *testing.T) {
	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "", "", "")
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	expected := "java keystore file foo.bar.jks with 1 certificate(s) created.\n"
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
	_ = os.Remove("foo.bar.jks")
}

func Test_exportCerts_cert_0_with_name(t *testing.T) {
	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", []int{0}, "", "", "file-name.jks")
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	expected := "java keystore file file-name.jks with 1 certificate(s) created.\n"
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
	_ = os.Remove("file-name.jks")
}

func Test_exportCerts_cert_1(t *testing.T) {
	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", []int{1}, "", "", "")
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	expected := "java keystore file foo.bar.jks with 0 certificate(s) created.\n"
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
	_ = os.Remove("foo.bar.jks")
}

func Test_exportCerts_to_existing_empty_jks(t *testing.T) {
	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts([]*x509.Certificate{test.NewCert(t)}, "https://foo.bar", nil, "../../testdata/empty.jks", "changeit", "")
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	expected := `Using existing java keystore ../../testdata/empty.jks to add the new certificates
java keystore file foo.bar.jks with 1 additional certificate(s) created.
`
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
	_ = os.Remove("foo.bar.jks")
}

func Test_exportCerts_to_existing_jks_duplicate(t *testing.T) {
	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts(
		[]*x509.Certificate{test.NewCert(t)},
		"https://foo.bar",
		nil,
		"../../testdata/geotrust.jks",
		"changeit",
		"",
	)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	expected := `Using existing java keystore ../../testdata/geotrust.jks to add the new certificates
java keystore file foo.bar.jks with 0 additional certificate(s) created.
`
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
	_ = os.Remove("foo.bar.jks")
}

func Test_exportCerts_to_existing_jks_additional(t *testing.T) {
	out, revert := mockPrintTarget()
	defer revert()

	err := exportCerts(
		[]*x509.Certificate{test.NewCert(t)},
		"https://foo.bar",
		nil,
		"../../testdata/google.jks",
		"changeit",
		"",
	)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	expected := `Using existing java keystore ../../testdata/google.jks to add the new certificates
java keystore file foo.bar.jks with 1 additional certificate(s) created.
`
	if out.String() != expected {
		t.Errorf("expected %q, but got %q", expected, out.String())
	}
	_ = os.Remove("foo.bar.jks")
}

func mockPrintTarget() (*bytes.Buffer, func()) {
	bak := out
	mock := new(bytes.Buffer)
	out = mock
	return mock, func() {
		out = bak
	}
}
