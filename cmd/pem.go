package cmd

import (
	"github.com/bakito/cert-fetcher/cert/pem"
	"github.com/spf13/cobra"
)

// pemCmd represents the pem command
var pemCmd = &cobra.Command{
	Version: version,
	Use:     "pem",
	Short:   "store the certificates as pem file",
	Long:    "store the certificates as pem file",

	RunE: func(cmd *cobra.Command, args []string) error {
		return pem.ExportTo(targetURL, certIndexes, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(pemCmd)
}
