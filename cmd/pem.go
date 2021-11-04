package cmd

import (
	"github.com/bakito/cert-fetcher/cert/pem"
	"github.com/spf13/cobra"
)

// pemCmd represents the pem command
var pemCmd = &cobra.Command{
	Version:   version,
	Use:       "pem [url]",
	Short:     "store the certificates as pem file",
	Long:      "store the certificates as pem file",
	ValidArgs: []string{"url"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return pem.ExportTo(args[0], certIndexes, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(pemCmd)
}
