package pem

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	c "github.com/bakito/cert-fetcher/cert"
)

// Export Export the certificates from the target URL into a pem file
func Export(targetURL string, certIndexes []int, outputFile string) error {
	certs, err := c.FetchCertificates(targetURL)
	if err != nil {
		return err
	}

	var pemBytes bytes.Buffer
	cnt := 0
	for i, cert := range certs {
		if c.IsToExport(certIndexes, i) {
			c.PrintAdd(i, cert)
			err := toPEM(&pemBytes, cert)
			if err != nil {
				return err
			}
			cnt++
		} else {
			c.PrintSkip(i, cert)
		}
	}

	var fileName string
	if outputFile != "" {
		fileName = outputFile
	} else {
		u, _ := url.Parse(targetURL)
		fileName = u.Host + ".pem"
	}
	f, err := os.Create(fileName)

	if err != nil {
		return err
	}

	defer f.Close()
	f.Write(pemBytes.Bytes())
	fmt.Printf("pem file %s with %d certificate(s) created.\n", fileName, cnt)
	return nil
}

func toPEM(pemBytes *bytes.Buffer, cert *x509.Certificate) error {
	return pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
