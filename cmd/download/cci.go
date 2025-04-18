package download

import (
	"github.com/jramscom/stigcli/stig"
	"github.com/spf13/cobra"
)

// Define the `cci` subcommand
var cciCmd = &cobra.Command{
	Use:   "cci",
	Short: "Download a copy of most recent CCI file and extract xml",
	Long:  `Download a copy of most recent CCI file and extract xml`,
	Run: func(cmd *cobra.Command, args []string) {
		outputDirectory := "."
		if len(args) > 0 {
			outputDirectory = args[0]
		}
		stig.Download_cci(outputDirectory)
	},
}

// Initialize the `cci` subcommand
func init() {
	// Attach the `cci` subcommand to the `download` command
	DownloadCmd.AddCommand(cciCmd)
}
