package cmd

import (
	"github.com/jramscom/stigcli/stig"
	"github.com/spf13/cobra"
)

var cci_xml_path string

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.PersistentFlags().StringVar(&cci_xml_path, "cci_xml_path", "", "The path to the CCI XML file")
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a CSV summary report file for all STIG Checklist",
	Long:  `Generates a CSV report of STIG ID by extracting information from checklist files. The command accepts an argument of direcotry containing CKL and CKLB files. If no argument is provided the command looks in the current working directory`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		var stigDirectory string = "."
		if len(args) > 0 {
			stigDirectory = args[0]
		}

		stig.GenerateReport(stigDirectory, cci_xml_path)
	},
}
