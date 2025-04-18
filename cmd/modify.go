package cmd

import (
	"github.com/jramscom/stigcli/stig"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(modifyCmd)
	modifyCmd.PersistentFlags().StringVar(&stigUpdateDirectory, "stigUpdateDirectory", "", "The directory path to STIG update.")
}

var stigUpdateDirectory string

var modifyCmd = &cobra.Command{
	Use:   "modify",
	Short: "Update STIG Checklist Files in bulk with a CSV STIG Update Rules file",
	Long:  ` csvfile stigdirectory. `,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var stigDirectory string = "."
		if len(args) > 1 {
			stigDirectory = args[1]
		}
		stig.UpdateSTIGfile(stigDirectory, args[0], stigUpdateDirectory)
	},
}
