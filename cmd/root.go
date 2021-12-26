package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/bakito/cert-fetcher/cert"
	"github.com/spf13/cobra"
)

var (
	outputFile  string
	certIndexes []int
	version     string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Version:   version,
	Use:       "cert-fetcher [url]",
	Short:     "Fetch client certificates from https urls",
	Long:      "A go application that fetches public certificates from https sites and stores them into different output formats.",
	ValidArgs: []string{"url"},
	Args:      urlArg,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cert.Print(args[0])
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
	rootCmd.PersistentFlags().StringVarP(&outputFile, "out-file", "o", "", "the output file")
	rootCmd.PersistentFlags().IntSliceVarP(&certIndexes, "import-at", "i", make([]int, 0), "import the certificates at the given indexes")
}

func urlArg(_ *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("url argument must be provided")
	}
	u, err := url.Parse(args[0])
	if err != nil {
		return fmt.Errorf("url is invalid: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("url schema must be https")
	}
	return err
}
