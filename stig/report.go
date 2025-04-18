package stig

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type reportItem struct {
	Filename       string
	Id             string
	Title          string
	Severity       string
	Comment        string
	Status         string
	CCI_ID         string
	FindingDetails string
}

func GenerateReport(stigDirectory string, cciXmlPath string) {

	err := checkDirectoryAccess(stigDirectory)
	if err != nil {
		log.Fatal(err.Error())
	}

	var includeCciInformation bool = false
	var ccilist CCILIST
	if cciXmlPath != "" {
		includeCciInformation = true

		if _, err := os.Stat(cciXmlPath); errors.Is(err, os.ErrNotExist) {
			log.Fatal("The CCI File does't exist or you don't have permission to access it.")
		}

		ccilist = parseCCIs(cciXmlPath)
		//ValidateCCIfilepathhere
	}

	//Check that the directory exists

	entries, err := os.ReadDir(stigDirectory)
	if err != nil {
		log.Fatal(err)
	}

	stigOutputfile, err := os.Create("stig_report_" + strconv.FormatInt(time.Now().Unix(), 10) + ".csv")
	if err != nil {
		log.Fatal(err.Error())
	}

	if includeCciInformation {
		stigOutputfile.Write([]byte("Filename,Id,Severity,Status,Title,Comment,FindingDetails,CCI,Mapping\n"))
	} else {
		stigOutputfile.Write([]byte("Filename,Id,Severity,Status,Title,Comment,FindingDetails\n"))
	}

	for _, checkListFile := range entries {

		if strings.HasSuffix(checkListFile.Name(), "ckl") {
			checklist := parseSTIG(stigDirectory + "/" + checkListFile.Name())
			reportItems := stigToReportItemsCkl(checklist, checkListFile.Name())
			for _, item := range reportItems {

				if includeCciInformation {
					ccitext := getCCIItemsByCCIID(item.CCI_ID, &ccilist)
					stigOutputfile.Write([]byte(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n", item.Filename, item.Id, item.Severity, item.Status, item.Title, item.Comment, item.FindingDetails, item.CCI_ID, ccitext)))
				} else {
					stigOutputfile.Write([]byte(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n", item.Filename, item.Id, item.Severity, item.Status, item.Title, item.Comment, item.FindingDetails)))
				}

			}
		}
		if strings.HasSuffix(checkListFile.Name(), "cklb") {

			checklist := parseSTIGv2(stigDirectory + "/" + checkListFile.Name())
			reportItems := stigToReportItemsCklb(checklist, checkListFile.Name())

			for _, item := range reportItems {
				if includeCciInformation {
					ccitext := getCCIItemsByCCIID(item.CCI_ID, &ccilist)
					stigOutputfile.Write([]byte(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n", item.Filename, item.Id, item.Severity, item.Status, item.Title, item.Comment, item.FindingDetails, item.CCI_ID, ccitext)))
				} else {
					stigOutputfile.Write([]byte(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n", item.Filename, item.Id, item.Severity, item.Status, item.Title, item.Comment, item.FindingDetails)))
				}
			}

		}

	}
	defer stigOutputfile.Close()
}

func stigToReportItemsCklb(checklist CHECKLISTjson, checklistfile string) []reportItem {
	var reportItems []reportItem

	// Iterate through vulnerabilities
	for _, rule := range checklist.Stigs[len(checklist.Stigs)-1].Rules {

		var item = reportItem{}
		findings := rule.FindingDetails
		findings = strings.Replace(findings, "\n", "", -1)
		findings = strings.Replace(findings, ",", " ", -1)
		item.FindingDetails = findings

		item.Status = rule.Status
		item.Filename = checklistfile

		comments := rule.Comment
		comments = strings.Replace(comments, "\n", "", -1)
		comments = strings.Replace(comments, ",", " ", -1)
		item.Comment = comments

		item.Severity = rule.Severity
		item.Title = rule.RuleTitle
		item.Title = strings.ReplaceAll(item.Title, "\n", " ")
		item.Title = strings.ReplaceAll(item.Title, ",", " ")
		item.Id = rule.Id
		item.CCI_ID = rule.CCIS[len(rule.CCIS)-1]

		reportItems = append(reportItems, item)
	}

	return reportItems

}

func stigToReportItemsCkl(checklist CHECKLIST, checklistfile string) []reportItem {
	var reportItems []reportItem

	// Iterate through vulnerabilities
	for _, vuln := range checklist.Stigs.ISTIG.Vulnerabilities {

		var item = reportItem{}
		item.Status = vuln.Status
		item.Filename = checklistfile

		comments := vuln.Comment
		comments = strings.Replace(comments, "\n", "", -1)
		comments = strings.Replace(comments, ",", " ", -1)
		item.Comment = comments

		findings := vuln.FindingDetails
		findings = strings.Replace(findings, "\n", "", -1)
		findings = strings.Replace(findings, ",", " ", -1)
		item.FindingDetails = findings

		// Iterate through STIG_DATA
		for _, data := range vuln.StigData {
			switch data.Attribute {
			case "Severity":
				item.Severity = data.Data
			case "Vuln_Num":
				item.Id = data.Data
			case "Rule_Title":
				title := data.Data
				title = strings.Replace(title, "\n", "", -1)
				title = strings.Replace(title, ",", " ", -1)
				item.Title = title
			case "CCI_REF":
				item.CCI_ID = data.Data
			}

		}
		reportItems = append(reportItems, item)
	}

	return reportItems

}

func getCCIItemsByCCIID(ccidstring string, ccilistdef *CCILIST) string {

	cci_string := ""
	for _, i := range ccilistdef.CCIItems.CCIs {
		if ccidstring == i.ID {
			cci_string = i.References[len(i.References)-1].Title + " " + i.References[len(i.References)-1].Index
			break
		}

	}
	return cci_string
}
