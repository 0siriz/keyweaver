package kw

import (
	"github.com/0siriz/keyweaver/internal/version"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "kw",
		Short:   "Keyweaver CLI",
		Version: version.Version,
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
	}

	cmd.SetVersionTemplate("{{.Version}}\n")

	return cmd
}
