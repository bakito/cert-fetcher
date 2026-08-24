package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
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

var out io.Writer = os.Stdout // modified during testing

// Print all certificates for the given target URL.
func Print(targetURL string) error {
	certs, err := FetchCertificates(targetURL)
	if err != nil {
		return err
	}
	for i, cert := range certs {
		if _, err = fmt.Fprintf(
			out,
			certTemplate,
			i,
			cert.Subject.CommonName,
			cert.Issuer.CommonName,
			cert.NotBefore.In(time.UTC).String(),
			cert.NotAfter.In(time.UTC).String(),
		); err != nil {
			return err
		}
	}
	return nil
}

// FetchCertificates fetch the certificate chain from te target URL.
func FetchCertificates(targetURL string) ([]*x509.Certificate, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// #nosec G402 we are checking the cert, hence we allow insecure ones
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	// #nosec G107
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		return resp.TLS.PeerCertificates, err
	}
	return nil, errors.New("could not find any certificates")
}

// IsToExport check whether the current index is to be exported.
func IsToExport(certIndexes []int, i int) bool {
	if len(certIndexes) == 0 {
		return true
	}
	return slices.Contains(certIndexes, i)
}

// PrintAdd print an add statement.
func PrintAdd(i int, cert *x509.Certificate) {
	_, _ = fmt.Fprintf(out, " + Adding   certificate #%d: %s\n", i, cert.Subject.CommonName)
}

// PrintSkip print an skip statement.
func PrintSkip(i int, cert *x509.Certificate) {
	PrintSkipDetailed(i, cert, "")
}

// PrintSkipDetailed print an skip statement.
func PrintSkipDetailed(i int, cert *x509.Certificate, detail string) {
	_, _ = fmt.Fprintf(out, " - Skipping certificate #%d: %s %s\n", i, cert.Subject.CommonName, detail)
}
