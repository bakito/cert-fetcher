package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	certTemplate string = `Certificate #%d:
Subject: %s 
Issuer: %s
NotBefore: %s
NotAfter: %s

`
)

var (
	loc           = time.Local
	out io.Writer = os.Stdout // modified during testing
)

// Print Print all certificates fir the given target URL
func Print(targetURL string) error {
	certs, err := FetchCertificates(targetURL)
	if err != nil {
		return err
	}
	for i, cert := range certs {
		if _, err = fmt.Fprintf(out, certTemplate, i, cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotBefore.In(loc).String(), cert.NotAfter.In(loc).String()); err != nil {
			return err
		}
	}
	return nil
}

// FetchCertificates fetch the certificate chain from te target URL
func FetchCertificates(targetURL string) ([]*x509.Certificate, error) {
	// #nosec G402 we are checking the cert, hence we allow insecure ones
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	// #nosec G107
	resp, err := http.Get(targetURL)

	if err != nil {
		return nil, err
	}

	if resp.TLS != nil {
		return resp.TLS.PeerCertificates, err
	}
	return nil, fmt.Errorf("could not find any certificates")
}

// IsToExport check whether the current index is to be exported
func IsToExport(certIndexes []int, i int) bool {
	if len(certIndexes) == 0 {
		return true
	}
	for _, a := range certIndexes {
		if a == i {
			return true
		}
	}
	return false
}

// PrintAdd print an add statement
func PrintAdd(i int, cert *x509.Certificate) {
	_, _ = fmt.Fprintf(out, " + Adding   certificate #%d: %s\n", i, cert.Subject.CommonName)
}

// PrintSkip print an skip statement
func PrintSkip(i int, cert *x509.Certificate) {
	PrintSkipDetailed(i, cert, "")
}

// PrintSkipDetailed print an skip statement
func PrintSkipDetailed(i int, cert *x509.Certificate, detail string) {
	_, _ = fmt.Fprintf(out, " - Skipping certificate #%d: %s %s\n", i, cert.Subject.CommonName, detail)
}
