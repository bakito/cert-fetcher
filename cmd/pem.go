package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

// pemCmd represents the pem command
var pemCmd = &cobra.Command{
	Use:   "pem",
	Short: "store the certificates ad pem file",
	Long:  "store the certificates ad pem file",

	Run: func(cmd *cobra.Command, args []string) {

		certs := fetchCertificates()
		pem, err := certChainToPEM(certs)

		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		var fileName string
		if outputFile != "" {
			fileName = outputFile
		} else {
			u, _ := url.Parse(targetURL)
			fileName = u.Host + ".pem"
		}
		f, _ := os.Create(fileName)

		defer f.Close()
		f.Write(pem)
		log.Printf("pem file %s created.", fileName)
	},
}

func init() {
	rootCmd.AddCommand(pemCmd)
}

// CertChainToPEM is a utility function returns a PEM encoded chain of x509 Certificates, in the order they are passed
func certChainToPEM(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certChain {
		if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}
