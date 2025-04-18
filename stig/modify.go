package stig

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strings"
)

type updateItem struct {
	Id                   string
	HostName             string
	Status               string
	Comment              string
	FindingDetails       string
	StatusUpdate         string
	CommentUpdate        string
	FindingDetailsUpdate string
}

func UpdateSTIGfile(stigDirectory string, csvUpdateFilePath string, stigUpdateDirectory string) {

	directoryToSaveStigFile := ""
	if stigUpdateDirectory != "" {
		directoryToSaveStigFile = stigUpdateDirectory
	} else {
		directoryToSaveStigFile = stigDirectory
	}

	f, err := os.Open(csvUpdateFilePath)
	if err != nil {
		log.Fatal("Unable to read input file "+csvUpdateFilePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)

	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+csvUpdateFilePath, err)
	}
	//Check for header

	if len(records) == 0 {
		log.Fatal("CSV File has no rows. Please input a valid CSV Files")
	}

	if len(records[0]) != 8 {
		log.Fatal("Invalid number of colss provided in CSV Files")

	}
	//Validate header
	if records[0][0] != "Id" || records[0][1] != "Hostname" || records[0][2] != "Status" || records[0][3] != "Comment" || records[0][4] != "FindingDetails" || records[0][5] != "StatusUpdate" || records[0][6] != "CommentUpdate" || records[0][7] != "FindingDetailsUpdate" {
		log.Fatal("Invalid header provided. Please provide a valid CSV Header. Should be in the format of Id,Hostname,Status,Comment,FindingDetails,StatusUpdate,CommentUpdate,FindingDetailsUpdate")
	}
	updateItems := []updateItem{}

	for i := range records {
		if i != 0 {
			updateItems = append(updateItems, updateItem{Id: records[i][0], HostName: records[i][1], Status: records[i][2], Comment: records[i][3], FindingDetails: records[i][4], StatusUpdate: records[i][5], CommentUpdate: records[i][6], FindingDetailsUpdate: records[i][7]})
		}

	}

	//Check that the directory exists

	entries, err := os.ReadDir(stigDirectory)
	if err != nil {
		log.Fatal(err)
	}

	for _, checkListFile := range entries {

		if strings.HasSuffix(checkListFile.Name(), "ckl") {
			checklist := parseSTIG(stigDirectory + "/" + checkListFile.Name())
			updateStigCkl(checklist, updateItems, directoryToSaveStigFile+"/"+checkListFile.Name())

		}
		if strings.HasSuffix(checkListFile.Name(), "cklb") {

			checklist := parseSTIGv2(stigDirectory + "/" + checkListFile.Name())
			updateStigCklb(checklist, updateItems, directoryToSaveStigFile+"/"+checkListFile.Name())

		}

	}
}

func updateStigCkl(checklist CHECKLIST, updates []updateItem, outputfile string) {

	file, err := os.Create(outputfile)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	fmt.Printf("Processing file %s\n", outputfile)
	for i := range checklist.Stigs.ISTIG.Vulnerabilities {
		vuln := &checklist.Stigs.ISTIG.Vulnerabilities[i] // Get a pointer to the original element

		stigid := ""

		for _, item := range vuln.StigData {
			if item.Attribute == "Vuln_Num" {
				stigid = item.Data
				break
			}
		}
		for _, updateItem := range updates {
			if (stigid == "" || updateItem.Id == stigid) &&
				(updateItem.HostName == "" || updateItem.HostName == checklist.Asset.HostName) &&
				(updateItem.FindingDetails == "" || (updateItem.FindingDetails == "-" && vuln.FindingDetails == "") || updateItem.FindingDetails == vuln.FindingDetails) &&
				(updateItem.Comment == "" || (updateItem.Comment == "-" && vuln.Comment == "") || updateItem.Comment == vuln.Comment) {

				if updateItem.StatusUpdate != "" && updateItem.StatusUpdate != vuln.Status {
					fmt.Printf("Updated Status of %s from %s to %s\n", stigid, vuln.Status, updateItem.StatusUpdate)
					vuln.Status = updateItem.StatusUpdate
				}
				if updateItem.CommentUpdate != "" {
					fmt.Printf("Updated Comment of %s from %s to %s\n", stigid, vuln.Comment, updateItem.CommentUpdate)
					vuln.Comment = updateItem.CommentUpdate
				}
				if updateItem.FindingDetailsUpdate != "" {
					fmt.Printf("Updated FindingDetails of %s from %s to %s\n", stigid, vuln.FindingDetails, updateItem.FindingDetailsUpdate)
					vuln.FindingDetails = updateItem.FindingDetailsUpdate
				}

			}

		}

	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ") // Optional: Pretty-print with indentation

	// Encode struct to XML and write to file
	if err := encoder.Encode(checklist); err != nil {
		fmt.Println("Error encoding XML:", err)
		return
	}

}

func updateStigCklb(checklist CHECKLISTjson, updates []updateItem, outputfile string) {

	file, err := os.Create(outputfile)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	fmt.Printf("Processing file %s", outputfile)
	for i := range checklist.Stigs[len(checklist.Stigs)-1].Rules {
		vuln := &checklist.Stigs[len(checklist.Stigs)-1].Rules[i] // Get a pointer to the original element
		for _, updateItem := range updates {
			if (vuln.Id == "" || updateItem.Id == vuln.Id) &&
				(updateItem.HostName == "" || updateItem.HostName == checklist.TargetData.HostName) &&
				(updateItem.FindingDetails == "" || (updateItem.FindingDetails == "-" && vuln.FindingDetails == "") || updateItem.FindingDetails == vuln.FindingDetails) &&
				(updateItem.Comment == "" || (updateItem.Comment == "-" && vuln.Comment == "") || updateItem.Comment == vuln.Comment) {
				println("Found Item for update")

				if updateItem.StatusUpdate != "" && updateItem.StatusUpdate != vuln.Status {
					fmt.Printf("Updated Status of %s from %s to %s\n", vuln.RuleID, vuln.Status, updateItem.StatusUpdate)
					vuln.Status = updateItem.StatusUpdate
				}
				if updateItem.CommentUpdate != "" {
					fmt.Printf("Updated Comment of %s from %s to %s\n", vuln.RuleID, vuln.Comment, updateItem.CommentUpdate)
					vuln.Comment = updateItem.CommentUpdate
				}
				if updateItem.FindingDetailsUpdate != "" {
					fmt.Printf("Updated FindingDetails of %s from %s to %s\n", vuln.RuleID, vuln.FindingDetails, updateItem.FindingDetailsUpdate)
					vuln.FindingDetails = updateItem.FindingDetailsUpdate
				}

			}

		}
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(checklist); err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}

}
