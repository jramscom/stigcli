package download

import (
	"github.com/jramscom/stigcli/stig"
	"github.com/spf13/cobra"
)

// Define the `cci` subcommand
var stigCmd = &cobra.Command{
	Use:   "stigs",
	Short: "Download copy of most recent STIG XML Files",
	Long:  `Download copy of most recent STIG XML Files. [directory]`,
	Run: func(cmd *cobra.Command, args []string) {
		outputDirectory := "."
		if len(args) > 0 {
			outputDirectory = args[0]
		}
		stig.Download_stigs(outputDirectory)
	},
}

// Initialize the `cci` subcommand
func init() {

	DownloadCmd.AddCommand(stigCmd)
}
