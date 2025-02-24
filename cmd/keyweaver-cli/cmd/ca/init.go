package ca

import (
	"github.com/0siriz/keyweaver/pkg/cert"
	"github.com/0siriz/keyweaver/pkg/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	config models.CAConfig
)

var initCmd = &cobra.Command{
	Use: "init",
	Short: "Initialize a CA",
	Run: func(cmd *cobra.Command, args []string) {
		loadCaConfig()
		cert.CreateCAs(config)
	},
}

func loadCaConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("ca")
	}

	err := viper.ReadInConfig()
	cobra.CheckErr(err)

	err = viper.Unmarshal(&config)
	cobra.CheckErr(err)
}

func init() {
	initCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./ca.yaml)")
}
