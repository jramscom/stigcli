package stig

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

func Download_cci(outputDirectory string) {
	if _, err := os.Stat("./temp"); err != nil {
		if os.IsNotExist(err) {

			if err := os.Mkdir("./temp", 0755); err != nil {
				fmt.Printf("failed to create parent directory: %v", err)
				return
			}

		}
	}

	filePath := "./temp"

	url := "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip"

	// Local file path to save the downloaded file
	filePath = filePath + "/U_CCI_List.zip"

	// Create the file
	out, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer out.Close()

	// Send a GET request to the URL
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error making GET request:", err)
		return
	}
	defer resp.Body.Close()

	// Copy the response body to the file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		fmt.Println("Error copying response body to file:", err)
		return
	}

	Unzip(filePath, "./temp")

	CopyFile("temp/U_CCI_List.xml", outputDirectory+"/U_CCI_List.xml")
	os.RemoveAll("./temp")

}

func Download_stigs(outputDirectory string) {
	if _, err := os.Stat("./temp"); err != nil {
		if os.IsNotExist(err) {

			if err := os.Mkdir("./temp", 0755); err != nil {
				fmt.Printf("failed to create parent directory: %v", err)
				return
			}

		}
	}
	if _, err := os.Stat("./temp/stig"); err != nil {
		if os.IsNotExist(err) {

			if err := os.Mkdir("./temp/stig", 0755); err != nil {
				fmt.Printf("failed to create parent directory: %v", err)
				return
			}

		}
	}
	if _, err := os.Stat("./temp/results"); err != nil {
		if os.IsNotExist(err) {

			if err := os.Mkdir("./temp/results", 0755); err != nil {
				fmt.Printf("failed to create parent directory: %v", err)
				return
			}

		}
	}

	filePath := "./temp"

	//
	//
	// https://public.cyber.mil/stigs/compilations/

	// Send a GET request to the URL
	resp, err := http.Get("https://public.cyber.mil/stigs/compilations/")
	if err != nil {
		fmt.Println("Error making GET request:", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	bodyString := string(bodyBytes)

	re := regexp.MustCompile(`https://dl\.dod\.cyber\.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_[^"]+?\.zip`)

	match := re.FindString(bodyString)
	if match != "" {
		fmt.Println("Matched URL:", match)
	} else {
		fmt.Println("No match found.")
	}

	url := match

	filename := path.Base(url)

	// Local file path to save the downloaded file
	filePath = filePath + "/" + filename

	// Create the file
	out, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer out.Close()

	// Send a GET request to the URL
	resp, err = http.Get(url)
	if err != nil {
		fmt.Println("Error making GET request:", err)
		return
	}
	defer resp.Body.Close()

	// Copy the response body to the file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		fmt.Println("Error copying response body to file:", err)
		return
	}

	Unzip(filePath, "./temp/stig")

	//STIG ops

	entries, err := os.ReadDir("./temp/stig/" + strings.TrimSuffix(filename, ".zip"))
	if err != nil {
		log.Fatal(err)
	}
	//Unzipping all files in
	for _, stigFile := range entries {
		if strings.HasSuffix(stigFile.Name(), ".zip") {
			println("UnZipping :" + stigFile.Name())
			Unzip("./temp/stig/"+strings.TrimSuffix(filename, ".zip")+"/"+stigFile.Name(), "./temp/results")

		}

	}

	var xmlFiles [][]string
	root := "./temp/results" // Root directory to start searching

	errWalk := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check if the file has a .xml extension

		if !info.IsDir() && filepath.Ext(path) == ".xml" {

			xmlFiles = append(xmlFiles, []string{path, info.Name()})
		}
		return nil
	})

	if errWalk != nil {
		fmt.Println("Error walking the directory:", err)
	}

	for _, stigFile := range xmlFiles {

		sourceFile, err := os.Open(stigFile[0])
		if err != nil {
			log.Fatal(err)
		}
		defer sourceFile.Close()

		destinationFile, err := os.Create(outputDirectory + "/" + stigFile[1])
		if err != nil {
			log.Fatal(err)
		}
		defer destinationFile.Close()

		_, err = io.Copy(destinationFile, sourceFile)
		if err != nil {
			log.Fatal(err)
		}

	}

}
