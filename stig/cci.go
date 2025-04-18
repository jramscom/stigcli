package stig

import (
	"encoding/xml"
	"log"
	"os"
)

type CCILIST struct {
	XMLName  xml.Name `xml:"cci_list"`  // Top-level wrapper element
	CCIItems CCIItems `xml:"cci_items"` // Intermediate `cci_items` element
}

type CCIItems struct {
	CCIs []CCIItem `xml:"cci_item"` // Slice of `cci_item` elements
}

type CCIItem struct {
	ID          string      `xml:"id,attr"`
	Status      string      `xml:"status"`
	PublishDate string      `xml:"publishdate"`
	Contributor string      `xml:"contributor"`
	Definition  string      `xml:"definition"`
	Type        string      `xml:"type"`
	References  []Reference `xml:"references>reference"`
}

type Reference struct {
	Creator  string `xml:"creator,attr"`
	Title    string `xml:"title,attr"`
	Version  string `xml:"version,attr"`
	Location string `xml:"location,attr"`
	Index    string `xml:"index,attr"`
}

func parseCCIs(cciFileName string) CCILIST {

	file, err := os.Open(cciFileName)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	var ccilist CCILIST

	// Create a new XML decoder
	decoder := xml.NewDecoder(file)

	// Decode the XML into the struct
	err = decoder.Decode(&ccilist)
	if err != nil {
		log.Fatalf("Error decoding XML: %v", err)
	}
	//fmt.Println("Length: ", len(ccilist.CCIItems.CCIs))
	return ccilist
}
