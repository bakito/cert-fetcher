package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
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
	targetURL   string
	outputFile  string
	certIndexes []int
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cert-fetcher",
	Short: "Fetch client certificates from https urls",
	Long:  `A go application that fetches public certificates from https sites and stores them into different output formates.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		certs, err := fetchCertificates()
		if err != nil {
			return err
		}

		loc := time.Local
		for i, cert := range certs {
			fmt.Printf(certTemplate, i, cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotBefore.In(loc).String(), cert.NotAfter.In(loc).String())
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&targetURL, "url", "u", "", "the URL to fetch the certificate from")
	rootCmd.MarkPersistentFlagRequired("url")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "out-file", "o", "", "the output file")
	rootCmd.PersistentFlags().IntSliceVarP(&certIndexes, "import-at", "i", make([]int, 0), "import the certificates at the given indexes")
}

func fetchCertificates() ([]*x509.Certificate, error) {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	resp, err := http.Get(targetURL)

	if err != nil {
		return nil, err
	}

	if resp.TLS != nil {
		return resp.TLS.PeerCertificates, err
	}
	return nil, fmt.Errorf("Could not find any certificates")
}

func isToExport(i int) bool {
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
