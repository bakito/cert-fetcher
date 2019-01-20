package cmd

import (
	"fmt"
	"os"

	"github.com/bakito/cert-fetcher/cert"
	"github.com/spf13/cobra"
)

var (
	targetURL   string
	outputFile  string
	certIndexes []int
	version     string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Version: version,
	Use:     "cert-fetcher",
	Short:   "Fetch client certificates from https urls",
	Long:    "A go application that fetches public certificates from https sites and stores them into different output formates.",
	RunE: func(cmd *cobra.Command, args []string) error {

		return cert.Print(targetURL)
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
