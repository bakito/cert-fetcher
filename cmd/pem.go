package cmd

import (
	"github.com/spf13/cobra"

	"github.com/bakito/cert-fetcher/cert/pem"
)

// pemCmd represents the pem command.
var pemCmd = &cobra.Command{
	Version:   version,
	Use:       "pem [url]",
	Short:     "store the certificates as pem file",
	Long:      "store the certificates as pem file",
	ValidArgs: []string{"url"},
	Args:      urlArg,
	RunE: func(_ *cobra.Command, args []string) error {
		return pem.ExportTo(args[0], certIndexes, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(pemCmd)
}
