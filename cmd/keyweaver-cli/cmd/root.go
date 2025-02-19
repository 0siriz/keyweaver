package cmd

import (
	"fmt"
	"os"

	"github.com/0siriz/keyweaver/cmd/keyweaver-cli/cmd/ca"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "keyweaver-cli",
	Short: "A toolkit for setting up and working with a Public Key Infrastructure",
	Long: `CLI tool for setting up and managing a KeyWeaver Public Key Infrastruture`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(ca.CaCmd)
}
