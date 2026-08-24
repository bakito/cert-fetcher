package pem

import (
	"crypto/x509"
	"testing"

	"github.com/bakito/cert-fetcher/cert/test"
)

func Test_exportCerts_min(t *testing.T) {
	_, cnt, err := exportCerts([]*x509.Certificate{test.NewCert(t)}, nil)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	if cnt != 1 {
		t.Errorf("expected count 1, but got %d", cnt)
	}
}

func Test_exportCerts_cert_0_with_name(t *testing.T) {
	_, cnt, err := exportCerts([]*x509.Certificate{test.NewCert(t)}, []int{0})
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	if cnt != 1 {
		t.Errorf("expected count 1, but got %d", cnt)
	}
}

func Test_exportCerts_cert_1(t *testing.T) {
	_, cnt, err := exportCerts([]*x509.Certificate{test.NewCert(t)}, []int{1})
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
	if cnt != 0 {
		t.Errorf("expected count 0, but got %d", cnt)
	}
}
