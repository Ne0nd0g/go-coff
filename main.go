package main

import (
	// Standard
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Ne0nd0g/go-coff/coff"
)

var verbose bool
var debug bool

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	filePath := flag.String("bof", "", "File path to the Beacon Object File (BOF)")
	flag.Parse()

	if *filePath == "" {
		log.Fatal("An input object filepath was not provided with the -bof flag")
	}

	// COFF Library Settings
	coff.Verbose = verbose
	coff.Debug = debug

	// Read in the file
	bof, err := read(*filePath)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error reading the file: %s", err))
	}
	fmt.Printf("[+] Successfully read in the file: %s\n", *filePath)

	if debug {
		fmt.Printf(fmt.Sprintf("Read in %d bytes\n", len(bof)))
	}

	// Parse the COFF
	obj, err := coff.ParseObject(bof)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error parsing the COFF: %s", err))
	}
	fmt.Printf("[+] Successfully parsed the COFF\n")

	// Load the COFF
	err = obj.Load()
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error loading the object file:\n%s", err))
	}
	fmt.Printf("[+] Successfully loaded the COFF\n")

	// Execute the COFF
	err = obj.Run("go")
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error executing the object file:\n%s", err))
	}
	fmt.Printf("[+] Successfully executed the COFF\n")
}

// read validates the provided file path exists, reads in the entire file as bytes, and returns them
func read(filePath string) ([]byte, error) {
	if verbose {
		fmt.Println(fmt.Sprintf("[-] Verifying file exists %s", filePath))
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
	}

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG] FileInfo: %+v", fileInfo))
	}

	if verbose {
		fmt.Println(fmt.Sprintf("[-] Reading in file %s", filePath))
	}

	return os.ReadFile(filePath)
}
