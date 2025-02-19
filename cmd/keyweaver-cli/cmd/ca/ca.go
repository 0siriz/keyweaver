package ca

import (
	"os"

	"github.com/spf13/cobra"
)

var CaCmd = &cobra.Command{
	Use: "ca",
	Short: "Certificate Authority",
	Long: `Tools for handling a Certificate Authority`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

func init() {

}
