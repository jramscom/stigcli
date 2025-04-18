package stig

import (
	"encoding/xml"
	"log"
	"os"
)

type CHECKLIST struct {
	Asset Asset `xml:"ASSET"`
	Stigs STIGS `xml:"STIGS"`
}

type Asset struct {
	XMLName       xml.Name `xml:"ASSET"`
	Role          string   `xml:"ROLE"`
	AssetType     string   `xml:"ASSET_TYPE"`
	Marking       string   `xml:"MARKING"`
	HostName      string   `xml:"HOST_NAME"`
	HostIP        string   `xml:"HOST_IP"`
	HostMAC       string   `xml:"HOST_MAC"`
	HostFQDN      string   `xml:"HOST_FQDN"`
	TargetComment string   `xml:"TARGET_COMMENT"`
	TechArea      string   `xml:"TECH_AREA"`
	TargetKey     string   `xml:"TARGET_KEY"`
	WebOrDatabase string   `xml:"WEB_OR_DATABASE"`
	WebDBSite     string   `xml:"WEB_DB_SITE"`
	WebDBInstance string   `xml:"WEB_DB_INSTANCE"`
}

type STIGS struct {
	ISTIG ISTIG `xml:"iSTIG"`
}

type Overrides struct {
	Severity *Severity `xml:"severity,omitempty"`
}

type Severity struct {
	Severity *string `xml:"severity,omitempty"`
	Reason   *string `xml:"reason,omitempty"`
}

type ISTIG struct {
	STIGInfo        STIGInfo `xml:"STIG_INFO"`
	Vulnerabilities []VULN   `xml:"VULN"`
}

type SIData struct {
	XMLName xml.Name `xml:"SI_DATA"`
	SIDName string   `xml:"SID_NAME"`
	SIDData string   `xml:"SID_DATA"`
}

type STIGInfo struct {
	XMLName xml.Name `xml:"STIG_INFO"`
	SIData  []SIData `xml:"SI_DATA"`
}

type VULN struct {
	StigData              []STIG_DATA `xml:"STIG_DATA"`
	Status                string      `xml:"STATUS"`
	FindingDetails        string      `xml:"FINDING_DETAILS"`
	Comment               string      `xml:"COMMENTS"`
	SeverityOverride      string      `xml:"SEVERITY_OVERRIDE"`
	SeverityJustification string      `xml:"SEVERITY_JUSTIFICATION"`
}

type STIG_DATA struct {
	Attribute string `xml:"VULN_ATTRIBUTE"`
	Data      string `xml:"ATTRIBUTE_DATA"`
}

func parseSTIG(checklistfile string) CHECKLIST {

	file, err := os.Open(checklistfile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	var checklist CHECKLIST

	// Create a new XML decoder
	decoder := xml.NewDecoder(file)

	// Decode the XML into the struct
	err = decoder.Decode(&checklist)
	if err != nil {
		log.Fatalf("Error decoding XML: %v", err)
	}

	return checklist
}

func GetStigDataByAttribute(data []STIG_DATA, attribute string) string {
	for _, item := range data {
		if item.Attribute == attribute {
			return item.Data
		}
	}
	return ""
}

func UpdateStigDataByAttribute(data []STIG_DATA, attribute string, value string) []STIG_DATA {
	for i := range data {
		if data[i].Attribute == attribute {
			data[i].Data = value
		}
	}
	return data
}

func GetStigDataElementsByAttribute(data []STIG_DATA, attribute string) []string {
	dataElements := []string{}
	for _, item := range data {
		if item.Attribute == attribute {
			dataElements = append(dataElements, item.Data)
		}
	}
	return dataElements
}

func removeByAttribute(data []STIG_DATA, attribute string) []STIG_DATA {
	// Create a new slice with capacity of the original (for efficiency)
	filtered := make([]STIG_DATA, 0, len(data))
	for _, item := range data {
		if item.Attribute != attribute {
			filtered = append(filtered, item)
		}
	}

	return filtered
}

func UpdateStigDataElementsByAttribute(data []STIG_DATA, attribute string, dataElements []string) []STIG_DATA {
	removedItems := removeByAttribute(data, attribute)

	for _, item := range dataElements {
		stigDataItem := STIG_DATA{Attribute: attribute, Data: item}

		removedItems = append(removedItems, stigDataItem)
	}
	return removedItems
}
