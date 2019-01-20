package cmd

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/spf13/cobra"
)

var (
	jksPassword    string
	jksSource      string
	jksCertIndexes []int
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
			fmt.Printf("Using existing java keystore %s to add the new certificates\n", jksSource)
		} else {
			ks = keystore.KeyStore{}
		}

		cnt := 0

		for i, cert := range certs {
			if isToExport(i) {
				if !alreadyContained(ks, cert, i) {
					fmt.Printf(" + Adding certificate #%d: %s\n", i, cert.Subject.CommonName)
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
				fmt.Printf(" - Skipping certificate #%d: %s\n", i, cert.Subject.CommonName)
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
		fmt.Printf("java keystore file %s with %d certificates created.\n", fileName, cnt)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(jksCmd)
	jksCmd.PersistentFlags().StringVarP(&jksPassword, "password", "p", "changeit", "the password to be used for the java keystore")
	jksCmd.PersistentFlags().StringVarP(&jksSource, "source", "s", "", "the source keystore to add the certs to")
	jksCmd.PersistentFlags().IntSliceVarP(&jksCertIndexes, "add", "a", make([]int, 0), "import the certificates at the given indexes")
}

func alias(cert *x509.Certificate) string {
	return fmt.Sprintf("%s (%s)", strings.ToLower(cert.Subject.CommonName), strings.ToLower(cert.Issuer.CommonName))
}

func isToExport(i int) bool {
	if len(jksCertIndexes) == 0 {
		return true
	}
	for _, a := range jksCertIndexes {
		if a == i {
			return true
		}
	}
	return false
}

func alreadyContained(ks keystore.KeyStore, cert *x509.Certificate, index int) bool {
	for a, e := range ks {
		switch tce := e.(type) {
		case *keystore.TrustedCertificateEntry:
			if reflect.DeepEqual(cert.Raw, tce.Certificate.Content) {
				fmt.Printf(" - Skipping certificate #%d '%s' that is already contained with alias '%s'\n", index, alias(cert), a)
				return true
			}
		}
	}
	return false
}
