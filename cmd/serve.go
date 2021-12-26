package cmd

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/bakito/cert-fetcher/cert/server"
	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Version: version,
	Use:     "serve [port]",
	Short:   "serve on tls port and print presented client certificates",
	Long:    "serve on tls port and print presented client certificates",
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("port argument must be provided")
		}

		_, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("port is invalid: %w", err)
		}
		return err
	},
	ValidArgs: []string{"port"},
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := strconv.Atoi(args[0])
		return server.Serve(port)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
