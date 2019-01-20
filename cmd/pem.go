package cmd

import (
	"github.com/bakito/cert-fetcher/cert/pem"
	"github.com/spf13/cobra"
)

// pemCmd represents the pem command
var pemCmd = &cobra.Command{
	Version: version,
	Use:     "pem",
	Short:   "store the certificates ad pem file",
	Long:    "store the certificates ad pem file",

	RunE: func(cmd *cobra.Command, args []string) error {
		return pem.Export(targetURL, certIndexes, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(pemCmd)
}
