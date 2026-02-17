package pem

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"

	c "github.com/bakito/cert-fetcher/cert"
)

var out io.Writer = os.Stdout // modified during testing

// ExportTo the certificates from the target URL into a pem file
func ExportTo(targetURL string, certIndexes []int, outputFile string) error {
	data, cnt, err := Export(targetURL, certIndexes)
	if err != nil {
		return err
	}
	var fileName string
	if outputFile != "" {
		fileName = outputFile
	} else {
		u, _ := url.Parse(targetURL)
		fileName = u.Host + ".pem"
	}
	// nolint:gosec // G703
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }() // #nosec G307
	_, _ = f.Write(data)
	_, _ = fmt.Fprintf(out, "pem file %s with %d certificate(s) created.\n", fileName, cnt)
	return nil
}

// Export the certificates from the target URL
func Export(targetURL string, certIndexes []int) ([]byte, int, error) {
	certs, err := c.FetchCertificates(targetURL)
	if err != nil {
		return nil, 0, err
	}
	return exportCerts(certs, certIndexes)
}

func exportCerts(certs []*x509.Certificate, certIndexes []int) ([]byte, int, error) {
	var pemBytes bytes.Buffer
	cnt := 0
	for i, cert := range certs {
		if c.IsToExport(certIndexes, i) {
			c.PrintAdd(i, cert)
			err := toPEM(&pemBytes, cert)
			if err != nil {
				return nil, 0, err
			}
			cnt++
		} else {
			c.PrintSkip(i, cert)
		}
	}

	return pemBytes.Bytes(), cnt, nil
}

func toPEM(pemBytes *bytes.Buffer, cert *x509.Certificate) error {
	return pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
