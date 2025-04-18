package download

import (
	"github.com/spf13/cobra"
)

// Define the `download` command
var DownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Commands related to downloading files",
	Long:  `Parent command for downloading STIG files.`,
}
