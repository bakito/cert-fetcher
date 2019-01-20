package jks

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	c "github.com/bakito/cert-fetcher/cert"
	keystore "github.com/pavel-v-chernykh/keystore-go"
)

// Export Export the certificates from the target URL into java keystore file
func Export(targetURL string, certIndexes []int, jksSource string, jksPassword string, outputFile string) error {
	certs, err := c.FetchCertificates(targetURL)
	if err != nil {
		return err
	}

	var ks keystore.KeyStore
	if jksSource != "" {

		s, err := os.Open(jksSource)
		if err != nil {
			return err
		}
		defer s.Close()
		ks, err = keystore.Decode(s, []byte(jksPassword))
		if err != nil {
			return err
		}
		fmt.Printf("Using existing java keystore %s to add the new certificates\n", jksSource)
	} else {
		ks = keystore.KeyStore{}
	}

	cnt := 0
	for i, cert := range certs {
		if c.IsToExport(certIndexes, i) {
			if !alreadyContained(ks, cert, i) {
				c.PrintAdd(i, cert)
				ce := &keystore.TrustedCertificateEntry{
					Entry: keystore.Entry{
						CreationDate: time.Now(),
					},
					Certificate: keystore.Certificate{
						Content: cert.Raw,
						Type:    "X.509",
					},
				}
				ce.CreationDate = time.Now()
				ks[alias(cert)] = ce
				cnt++
			}
		} else {
			c.PrintSkip(i, cert)
		}
	}

	var fileName string
	if outputFile != "" {
		fileName = outputFile
	} else {
		u, _ := url.Parse(targetURL)
		fileName = u.Host + ".jks"
	}

	k, _ := os.Create(fileName)
	defer k.Close()
	keystore.Encode(k, ks, []byte(jksPassword))
	fmt.Printf("java keystore file %s with %d certificate(s) created.\n", fileName, cnt)
	return nil
}

func alias(cert *x509.Certificate) string {
	return fmt.Sprintf("%s (%s)", strings.ToLower(cert.Subject.CommonName), strings.ToLower(cert.Issuer.CommonName))
}

func alreadyContained(ks keystore.KeyStore, cert *x509.Certificate, index int) bool {
	for a, e := range ks {
		switch tce := e.(type) {
		case *keystore.TrustedCertificateEntry:
			if reflect.DeepEqual(cert.Raw, tce.Certificate.Content) {
				c.PrintSkipDetailed(index, cert, fmt.Sprintf("that is already contained with alias '%s'", a))
				return true
			}
		}
	}
	return false
}
