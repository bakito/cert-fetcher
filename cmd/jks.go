package cmd

import (
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/spf13/cobra"
)

var (
	jskPassword = "changeit"
)

// jksCmd represents the jks command
var jksCmd = &cobra.Command{
	Use:   "jks",
	Short: "store the certificates into an java keystore",
	Long:  "store the certificates into an java keystore",
	Run: func(cmd *cobra.Command, args []string) {
		certs := fetchCertificates()
		ks := keystore.KeyStore{}

		for _, cert := range certs {
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
		keystore.Encode(k, ks, []byte(jskPassword))
		log.Printf("java keystore file %s created.", fileName)

	},
}

func init() {
	rootCmd.AddCommand(jksCmd)
	jksCmd.PersistentFlags().StringVarP(&jskPassword, "password", "p", "changeit", "the password to be used for the java keystore")
}

func alias(cert *x509.Certificate) string {
	return fmt.Sprintf("%s (%s)", strings.ToLower(cert.Subject.CommonName), strings.ToLower(cert.Issuer.CommonName))
}
