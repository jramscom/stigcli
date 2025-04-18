package cmd

import (
	"github.com/spf13/cobra"
	//"github.com/spf13/viper"
	"github.com/jramscom/stigcli/cmd/download"
)

var (
	// Used for flags.
	cfgFile     string
	userLicense string

	rootCmd = &cobra.Command{
		Use:   "stigcli",
		Short: "STIG CLI is a tool for working with STIG XML files in bulk.",
		Long:  `STIG CLI is a tool for working with STIG XML files in bulk. The CLI tool helps perform operations, reporting, and maintainence on STIG CKL and CKLB files in bulk, elminiating the need to perform manual operations individually with STIG Viewer`,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	//cobra.OnInitialize(initConfig)

	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	//rootCmd.PersistentFlags().StringP("author", "a", "YOUR NAME", "author name for copyright attribution")
	//rootCmd.PersistentFlags().StringVarP(&userLicense, "license", "l", "", "name of license for the project")
	//rootCmd.PersistentFlags().Bool("viper", true, "use Viper for configuration")
	//viper.BindPFlag("author", rootCmd.PersistentFlags().Lookup("author"))
	//viper.BindPFlag("useViper", rootCmd.PersistentFlags().Lookup("viper"))
	//viper.SetDefault("author", "NAME HERE <EMAIL ADDRESS>")
	//viper.SetDefault("license", "apache")

	//rootCmd.AddCommand(addCmd)
	//rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(download.DownloadCmd)

}

/* func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cobra")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
*/
