package cmd

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/spf13/cobra"
)

var (
	jksPassword string
	jksSource   string
)

// jksCmd represents the jks command
var jksCmd = &cobra.Command{
	Use:   "jks",
	Short: "store the certificates into an java keystore",
	Long:  "store the certificates into an java keystore",
	RunE: func(cmd *cobra.Command, args []string) error {
		certs, err := fetchCertificates()
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
		} else {
			ks = keystore.KeyStore{}
		}
		for i, cert := range certs {
			fmt.Printf("Adding certificate #%d: %s\n", i, cert.Subject.CommonName)
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
		keystore.Encode(k, ks, []byte(jksPassword))
		fmt.Printf("java keystore file %s with %d certificates created.\n", fileName, len(certs))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(jksCmd)
	jksCmd.PersistentFlags().StringVarP(&jksPassword, "password", "p", "changeit", "the password to be used for the java keystore")
	jksCmd.PersistentFlags().StringVarP(&jksSource, "source", "s", "", "the source keystore to add the certs to")
}

func alias(cert *x509.Certificate) string {
	return fmt.Sprintf("%s (%s)", strings.ToLower(cert.Subject.CommonName), strings.ToLower(cert.Issuer.CommonName))
}
