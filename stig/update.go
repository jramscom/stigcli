package stig

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func UpdateStig(stigDirectory string, benchmarkDirectory string, stigUpdateDirectory string, reportOnly bool) {

	directoryToSaveUpdates := ""
	if stigUpdateDirectory != "" {
		directoryToSaveUpdates = stigUpdateDirectory
	} else {
		directoryToSaveUpdates = stigDirectory
	}

	//Load all benchmarks into array
	err := checkDirectoryAccess(benchmarkDirectory)
	if err != nil {
		log.Fatal(err.Error())
	}

	entries, err := os.ReadDir(benchmarkDirectory)
	if err != nil {
		log.Fatal(err)
	}

	benchmarks := []Benchmark{}

	for _, benchmarkFile := range entries {
		if strings.HasSuffix(benchmarkFile.Name(), "xccdf.xml") {
			benchmark := parseBenchmark(benchmarkDirectory + "/" + benchmarkFile.Name())
			benchmarks = append(benchmarks, benchmark)

		}
	}

	err = checkDirectoryAccess(stigDirectory)
	if err != nil {
		log.Fatal(err.Error())
	}

	stigEntries, err := os.ReadDir(stigDirectory)
	if err != nil {
		log.Fatal(err)
	}

	reportOutputfile, err := os.Create(directoryToSaveUpdates + "/stig_update_report_" + strconv.FormatInt(time.Now().Unix(), 10) + ".txt")
	if err != nil {
		log.Fatal(err.Error())
	}

	for _, checkListFile := range stigEntries {

		if strings.HasSuffix(checkListFile.Name(), "ckl") {
			checklist := parseSTIG(stigDirectory + "/" + checkListFile.Name())

			stigId := ""
			stigVersion := ""
			stigRelease := ""

			for _, infoElement := range checklist.Stigs.ISTIG.STIGInfo.SIData {

				if infoElement.SIDName == "stigid" {
					stigId = infoElement.SIDData
				}

				if infoElement.SIDName == "version" {
					stigVersion = infoElement.SIDData
				}
				if infoElement.SIDName == "releaseinfo" {
					stigRelease = infoElement.SIDData
				}

			}
			reportOutputfile.Write([]byte("Checking for updates on " + checkListFile.Name() + "\n"))
			//Now loop through STIG files
			for _, benchmark := range benchmarks {
				//Find the ID
				if benchmark.ID == stigId {
					reportOutputfile.Write([]byte("Found ID " + benchmark.ID + "\n"))

					stigReleaseNumber, err := extractReleaseNumber(stigRelease)

					if err != nil {
						log.Fatal("Error:", err)
					}
					benchmarkRelease := ""
					for _, plainText := range benchmark.PlainTexts {
						if plainText.ID == "release-info" {
							benchmarkRelease = plainText.Value
						}
					}
					benchmarkReleaseNumber, err := extractReleaseNumber(benchmarkRelease)

					if err != nil {
						log.Fatal("Error:", err)
					}

					if stigVersion < benchmark.Version || stigVersion == benchmark.Version && stigReleaseNumber < benchmarkReleaseNumber {

						reportOutputfile.Write([]byte(fmt.Sprintf("New STIG available version %s release %d \n", benchmark.Version, benchmarkReleaseNumber)))
						//First check to see if there is any new STIG items
						for _, group := range benchmark.Groups {

							var stigFound = false
							for i, vuln := range checklist.Stigs.ISTIG.Vulnerabilities {

								stigid := ""
								for _, item := range vuln.StigData {
									if item.Attribute == "Vuln_Num" {
										stigid = item.Data
										break
									}
								}
								if group.ID == stigid {
									//STIG Found

									reportOutputfile.Write([]byte("STIG " + stigid + " found in benchmark. Checking for updates.\n"))

									title := GetStigDataByAttribute(vuln.StigData, "Rule_Title")
									if title != group.Rules[len(group.Rules)-1].Title {
										reportOutputfile.Write([]byte(" --STIG Title changed \n"))

										checklist.Stigs.ISTIG.Vulnerabilities[i].StigData = UpdateStigDataByAttribute(vuln.StigData, "Rule_Title", group.Title)
									}

									checkContent := GetStigDataByAttribute(vuln.StigData, "Check_Content")
									if checkContent != group.Rules[len(group.Rules)-1].Check.CheckContent {
										reportOutputfile.Write([]byte(" -- Check Content changed \n"))
										checklist.Stigs.ISTIG.Vulnerabilities[i].StigData = UpdateStigDataByAttribute(vuln.StigData, "Check_Content", group.Rules[len(group.Rules)-1].Check.CheckContent)
									}
									fixText := GetStigDataByAttribute(vuln.StigData, "Fix_Text")
									if fixText != group.Rules[len(group.Rules)-1].FixText {
										reportOutputfile.Write([]byte("-- Fix Text changed \n"))
										checklist.Stigs.ISTIG.Vulnerabilities[i].StigData = UpdateStigDataByAttribute(vuln.StigData, "fixText", group.Rules[len(group.Rules)-1].FixText)
									}
									stigRef := GetStigDataByAttribute(vuln.StigData, "STIGRef")
									stigRefString := benchmark.Title + " :: Version " + benchmark.Version + ", " + benchmark.PlainTexts[0].Value
									if stigRef != stigRefString {
										reportOutputfile.Write([]byte(" -- STIG Ref  changed\n"))
										checklist.Stigs.ISTIG.Vulnerabilities[i].StigData = UpdateStigDataByAttribute(vuln.StigData, "STIGRef", stigRefString)
									}

									stigFound = true
									break

								}
							}
							if !stigFound {
								//This is where we want to add new STIG and all items
								reportOutputfile.Write([]byte("STIG " + group.ID + " not found. Inserting into checklist \n"))
								var newVulnItem = VULN{}

								newVulnItem.Status = "Open"
								stigData := []STIG_DATA{}
								stigData = append(stigData, STIG_DATA{Attribute: "Vuln_Num", Data: group.ID})
								stigData = append(stigData, STIG_DATA{Attribute: "Severity", Data: group.Rules[0].Severity})
								stigData = append(stigData, STIG_DATA{Attribute: "Group_Title", Data: group.Title})
								stigData = append(stigData, STIG_DATA{Attribute: "Rule_ID", Data: group.Rules[0].ID})
								stigData = append(stigData, STIG_DATA{Attribute: "Rule_Ver", Data: group.Rules[0].Version})
								stigData = append(stigData, STIG_DATA{Attribute: "Rule_Title", Data: group.Rules[0].Title})
								stigData = append(stigData, STIG_DATA{Attribute: "Vuln_Discuss", Data: group.Rules[0].Description})
								stigData = append(stigData, STIG_DATA{Attribute: "IA_Controls", Data: group.Rules[0].Title})
								stigData = append(stigData, STIG_DATA{Attribute: "Check_Content", Data: group.Rules[0].Check.CheckContent})
								stigData = append(stigData, STIG_DATA{Attribute: "Fix_Text", Data: group.Rules[0].FixText})
								stigData = append(stigData, STIG_DATA{Attribute: "False_Positives", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "False_Negatives", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Documentable", Data: "false"})
								stigData = append(stigData, STIG_DATA{Attribute: "Mitigations", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Potential_Impact", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Third_Party_Tools", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Mitigation_Control", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Responsibility", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Security_Override_Guidance", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Check_Content_Ref", Data: ""})
								stigData = append(stigData, STIG_DATA{Attribute: "Weight", Data: fmt.Sprintf("%.1f", group.Rules[0].Weight)})

								stigData = append(stigData, STIG_DATA{Attribute: "Class", Data: "Unclass"})
								stigData = append(stigData, STIG_DATA{Attribute: "STIGRef", Data: benchmark.Title + " :: Version " + benchmark.Version + ", " + benchmark.PlainTexts[0].Value})
								stigData = append(stigData, STIG_DATA{Attribute: "TargetKey", Data: group.Rules[0].ID})

								stig_id := uuid.New()

								stigData = append(stigData, STIG_DATA{Attribute: "STIG_UUID", Data: stig_id.String()})

								newVulnItem.StigData = stigData
								for _, ident := range group.Rules[len(group.Rules)-1].Idents {
									if ident.System == "http://cyber.mil/legacy" {
										stigData = append(stigData, STIG_DATA{Attribute: "LEGACY_ID", Data: ident.Value})
									}
								}

								for _, ident := range group.Rules[len(group.Rules)-1].Idents {
									if ident.System == "http://cyber.mil/cci" {
										stigData = append(stigData, STIG_DATA{Attribute: "CCI_REF", Data: ident.Value})
									}
								}

								checklist.Stigs.ISTIG.Vulnerabilities = append(checklist.Stigs.ISTIG.Vulnerabilities, newVulnItem)

							}

						}
						//Now check to see if there is any removals
						benchmarkFound := false
						for i := 0; i < len(checklist.Stigs.ISTIG.Vulnerabilities); {

							stigid := ""
							for _, item := range checklist.Stigs.ISTIG.Vulnerabilities[i].StigData {
								if item.Attribute == "Vuln_Num" {
									stigid = item.Data
									break
								}
							}

							for _, group := range benchmark.Groups {
								if group.ID == stigid {
									benchmarkFound = true
									break

								}
							}
							if !benchmarkFound {
								reportOutputfile.Write([]byte("STIG " + stigid + " not found in benchmark. Removing from checklist \n"))

								checklist.Stigs.ISTIG.Vulnerabilities = append(
									checklist.Stigs.ISTIG.Vulnerabilities[:i],
									checklist.Stigs.ISTIG.Vulnerabilities[i+1:]...,
								)
							} else {
								i++
							}
						}

					} else {
						reportOutputfile.Write([]byte(fmt.Sprintf("STIG is already at latest version %s release %d \n", stigVersion, stigReleaseNumber)))
					}

				}

			}

			file, err := os.Create(directoryToSaveUpdates + "/" + checkListFile.Name())
			if err != nil {
				fmt.Println("Error creating file:", err)
				return
			}
			defer file.Close()

			encoder := xml.NewEncoder(file)
			encoder.Indent("", "  ")

			// Encode struct to XML and write to file
			if err := encoder.Encode(checklist); err != nil {
				fmt.Println("Error encoding XML:", err)
				return
			}
		}
		if strings.HasSuffix(checkListFile.Name(), "cklb") {

			checklist := parseSTIGv2(stigDirectory + "/" + checkListFile.Name())

			stigBenchmarkDate, err := extractBenchmarkDate(checklist.Stigs[0].ReleaseInfo)
			if err != nil {
				log.Fatal("Malformed Checklist file - Invalid or missing STIG benchmark date")
			}
			stigId := checklist.Stigs[0].StigID
			reportOutputfile.Write([]byte("Checking for updates on " + checkListFile.Name() + "\n"))

			for _, benchmark := range benchmarks {

				if benchmark.ID == stigId {
					reportOutputfile.Write([]byte("Found ID " + benchmark.ID + "\n"))

					if err != nil {
						log.Fatal("Error:", err)
					}
					benchmarkReleaseInfo := ""
					for _, plainText := range benchmark.PlainTexts {
						if plainText.ID == "release-info" {
							benchmarkReleaseInfo = plainText.Value
						}
					}
					benchmarkDate, err := extractBenchmarkDate(benchmarkReleaseInfo)
					if err != nil {
						log.Fatal("Malformed Checklist file - Invalid or missing benchmark date")
					}

					if stigBenchmarkDate.Before(benchmarkDate) {

						reportOutputfile.Write([]byte(fmt.Sprintf("New STIG available version %s benchmark date %s \n", benchmark.Version, benchmarkDate)))
						//First check to see if there is any new STIG items
						for _, group := range benchmark.Groups {

							var stigFound = false
							for i, vuln := range checklist.Stigs[0].Rules {

								if group.ID == vuln.Id {
									//STIG Found
									reportOutputfile.Write([]byte("STIG " + vuln.Id + " found in benchmark. Checking for updates.\n"))

									if vuln.RuleTitle != group.Rules[len(group.Rules)-1].Title {
										reportOutputfile.Write([]byte(fmt.Sprint("-- STIG Title changed", vuln.RuleTitle, group.Rules[len(group.Rules)-1].Title)))
										checklist.Stigs[0].Rules[i].RuleTitle = group.Rules[len(group.Rules)-1].Title
									}

									if vuln.CheckContent != group.Rules[len(group.Rules)-1].Check.CheckContent {
										reportOutputfile.Write([]byte("-- Check Content  changed\n"))
										checklist.Stigs[0].Rules[i].CheckContent = group.Rules[len(group.Rules)-1].Check.CheckContent
									}

									if vuln.FixText != group.Rules[len(group.Rules)-1].FixText {
										reportOutputfile.Write([]byte("-- Fix Text changed\n"))
										checklist.Stigs[0].Rules[i].FixText = group.Rules[len(group.Rules)-1].FixText
									}

									stigFound = true
									break

								}
							}
							if !stigFound {
								//This is where we want to add new STIG and all items
								reportOutputfile.Write([]byte("STIG " + group.ID + " not found. Inserting into checklist \n"))

								var newVulnItem = RULEjson{}

								newVulnItem.Id = group.ID
								newVulnItem.GroupIDSrc = group.ID
								newVulnItem.GroupTitle = group.Rules[0].Title
								newVulnItem.Severity = group.Rules[0].Severity
								newVulnItem.Status = "open"
								newVulnItem.RuleID = group.Rules[0].ID[0 : len(newVulnItem.RuleID)-4]
								newVulnItem.RuleIDSrc = group.Rules[0].ID
								newVulnItem.RuleVersion = group.Rules[0].Version
								newVulnItem.RuleTitle = group.Rules[0].Title
								newVulnItem.Discussion = group.Rules[0].Description
								newVulnItem.IAControls = group.Rules[0].Title
								newVulnItem.CheckContent = group.Rules[0].Check.CheckContent
								newVulnItem.FixText = group.Rules[0].FixText
								newVulnItem.Documentable = "false"
								newVulnItem.Weight = fmt.Sprintf("%.1f", group.Rules[0].Weight)

								newVulnItem.Classification = "Unclassified"
								newVulnItem.CheckContentRef.Href = group.Rules[0].Check.CheckContentRef.Href
								newVulnItem.CheckContentRef.Name = group.Rules[0].Check.CheckContentRef.Name

								groupTreeData := []GroupTree{}
								groupTreeData = append(groupTreeData, GroupTree{ID: group.ID, Title: group.Title, Description: group.Description})
								newVulnItem.GroupTree = groupTreeData

								stig_id := uuid.New()
								newVulnItem.StigUUID = stig_id.String()

								legacyIds := []string{}
								for _, ident := range group.Rules[0].Idents {
									if ident.System == "http://cyber.mil/legacy" {
										legacyIds = append(legacyIds, ident.Value)
									}
								}
								newVulnItem.LegacyIDs = legacyIds

								ccis := []string{}
								for _, ident := range group.Rules[0].Idents {
									if ident.System == "http://cyber.mil/cci" {
										ccis = append(ccis, ident.Value)
									}
								}
								newVulnItem.CCIS = ccis

								checklist.Stigs[0].Rules = append(checklist.Stigs[0].Rules, newVulnItem)

							}

						}
						//Now check to see if there is any removals
						benchmarkFound := false
						for i := 0; i < len(checklist.Stigs[0].Rules); {

							for _, group := range benchmark.Groups {
								if group.ID == checklist.Stigs[0].Rules[0].Id {

									benchmarkFound = true
									break

								}
							}
							if !benchmarkFound {

								reportOutputfile.Write([]byte("STIG " + checklist.Stigs[0].Rules[i].Id + " not found in benchmark. Removing from checklist \n"))

								checklist.Stigs[0].Rules = append(
									checklist.Stigs[0].Rules[:i],
									checklist.Stigs[0].Rules[i+1:]...,
								)
							} else {
								i++
							}
						}

					} else {
						reportOutputfile.Write([]byte(fmt.Sprintf("STIG is already at latest benchmark %s ", stigBenchmarkDate)))
					}

				}

			}

			file, err := os.Create(directoryToSaveUpdates + "/" + checkListFile.Name())
			if err != nil {
				fmt.Println("Error creating file:", err)
				return
			}
			defer file.Close()

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")

			// Encode struct to XML and write to file
			if err := encoder.Encode(checklist); err != nil {
				fmt.Println("Error encoding JSON:", err)
				return
			}
		}

	}

}

// CKLB files do not contain the version number. Extracting the Benchmark Date. This probably should work for CLK files as well.
func extractBenchmarkDate(s string) (time.Time, error) {
	const prefix = "Benchmark Date: "
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return time.Time{}, fmt.Errorf("benchmark date not found")
	}

	dateStr := strings.TrimSpace(s[idx+len(prefix):])

	layout := "2 Jan 2006"
	t, err := time.Parse(layout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse date: %w", err)
	}

	return t, nil
}

func extractReleaseNumber(input string) (int, error) {
	// Define regex pattern to capture the release number
	re := regexp.MustCompile(`Release:\s*(\d+)`)
	match := re.FindStringSubmatch(input)

	// Check if we found a match
	if len(match) > 1 {
		releaseNumber, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		return releaseNumber, nil
	}
	return 0, fmt.Errorf("release number not found")
}

func extractBetween(text, tagName string) string {
	openTag := "&lt;" + tagName + "&gt;"
	closeTag := "&lt;/" + tagName + "&gt;"

	// Find the start index of the <tagName> ...
	startIdx := strings.Index(text, openTag)
	if startIdx == -1 {
		// If not found, return empty.
		return ""
	}

	// Move index to the character right after <tagName>...
	startIdx += len(openTag)

	// Find where </tagName> begins, starting from the character right after <tagName>
	endIdx := strings.Index(text[startIdx:], closeTag)
	if endIdx == -1 {
		// If not found, return empty.
		return ""
	}

	// endIdx is relative to startIdx, so total offset is startIdx + endIdx
	return text[startIdx : startIdx+endIdx]
}
