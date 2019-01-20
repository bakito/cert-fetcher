package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

// pemCmd represents the pem command
var pemCmd = &cobra.Command{
	Use:   "pem",
	Short: "store the certificates ad pem file",
	Long:  "store the certificates ad pem file",

	RunE: func(cmd *cobra.Command, args []string) error {

		certs, err := fetchCertificates()
		if err != nil {
			return err
		}

		pem, err := certChainToPEM(certs)

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
		f, err := os.Create(fileName)

		if err != nil {
			return err
		}

		defer f.Close()
		f.Write(pem)
		fmt.Printf("pem file %s with %d certificates created.\n", fileName, len(certs))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pemCmd)
}

// CertChainToPEM is a utility function returns a PEM encoded chain of x509 Certificates, in the order they are passed
func certChainToPEM(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for i, cert := range certChain {
		fmt.Printf("Adding certificate #%d: %s\n", i, cert.Subject.CommonName)
		if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}
