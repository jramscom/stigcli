package stig

import (
	"encoding/xml"
	"log"
	"os"
)

// Benchmark represents the top-level XML structure
type Benchmark struct {
	XMLName     xml.Name    `xml:"Benchmark"`
	ID          string      `xml:"id,attr"`
	XMLLang     string      `xml:"xml:lang,attr"`
	Status      Status      `xml:"status"`
	Title       string      `xml:"title"`
	Description string      `xml:"description"`
	Notice      Notice      `xml:"notice"`
	FrontMatter string      `xml:"front-matter"`
	RearMatter  string      `xml:"rear-matter"`
	Reference   Reference   `xml:"reference"`
	PlainTexts  []PlainText `xml:"plain-text"`
	Version     string      `xml:"version"`
	Profile     Profile     `xml:"Profile"`
	Groups      []Group     `xml:"Group"`
}

// Status represents the status information
type Status struct {
	Date  string `xml:"date,attr"`
	Value string `xml:",chardata"`
}

type PlainText struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

// Notice represents the terms of use notice
type Notice struct {
	ID      string `xml:"id,attr"`
	XMLLang string `xml:"xml:lang,attr"`
}

// Profile represents the profile structure
type Profile struct {
	ID          string `xml:"id,attr"`
	Title       string `xml:"title"`
	Description string `xml:"description"`
}

// Group represents the main security rule group
type Group struct {
	ID          string `xml:"id,attr"`
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Rules       []Rule `xml:"Rule"`
}

// Rule represents the rule inside the Group
type Rule struct {
	ID          string          `xml:"id,attr"`
	Weight      float64         `xml:"weight,attr"`
	Severity    string          `xml:"severity,attr"`
	Version     string          `xml:"version"`
	Title       string          `xml:"title"`
	Description string          `xml:"description"`
	References  []StigReference `xml:"reference"`
	Idents      []Ident         `xml:"ident"`
	FixText     string          `xml:"fixtext"`
	Fix         Fix             `xml:"fix"`
	Check       Check           `xml:"check"`
}

// Reference represents external references
type StigReference struct {
	Href       string `xml:"href,attr,omitempty"`
	Publisher  string `xml:"dc:publisher"`
	Source     string `xml:"dc:source,omitempty"`
	Type       string `xml:"dc:type,omitempty"`
	Subject    string `xml:"dc:subject,omitempty"`
	Identifier string `xml:"dc:identifier,omitempty"`
}

// Ident represents system identifiers
type Ident struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// Fix represents the fix information
type Fix struct {
	ID string `xml:"id,attr"`
}

// Check represents the check system
type Check struct {
	System          string              `xml:"system,attr"`
	CheckContentRef StigCheckContentRef `xml:"check-content-ref"`
	CheckContent    string              `xml:"check-content"`
}

// CheckContentRef represents check-content reference
type StigCheckContentRef struct {
	Href string `xml:"href,attr"`
	Name string `xml:"name,attr"`
}

func parseBenchmark(benchmarkFile string) Benchmark {

	file, err := os.Open(benchmarkFile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	var benchmark Benchmark

	// Create a new XML decoder
	decoder := xml.NewDecoder(file)

	// Decode the XML into the struct
	err = decoder.Decode(&benchmark)
	if err != nil {
		log.Fatalf("Error decoding XML: %v", err)
	}

	return benchmark
}
