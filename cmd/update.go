package cmd

import (
	"github.com/jramscom/stigcli/stig"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.PersistentFlags().BoolVar(&reportOnly, "reportOnly", false, "Only print report and don't update.")
	updateCmd.PersistentFlags().StringVar(&stigUpdatedVersionDirectory, "stigUpdatedVersionDirectory", "", "The directory path to STIG update.")
}

var reportOnly bool
var stigUpdatedVersionDirectory string

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a STIG to the latest version",
	Long:  ` benchmarkDirectory stigDirectory. `,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {

		stig.UpdateStig(args[0], args[1], stigUpdatedVersionDirectory, reportOnly)
	},
}
