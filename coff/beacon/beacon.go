package beacon

// https://www.cobaltstrike.com/help-beacon-object-files
// https://www.cobaltstrike.com/downloads/beacon.h

import (
	"fmt"

	// X-Packages
	"golang.org/x/sys/windows"
)

// Data Parser API
// The Data Parser API extracts arguments packed with Aggressor Script's &bof_pack function.

// typedef struct {
//  char * original; /* the original buffer [so we can free it] */
//	char * buffer;   /* current pointer into our buffer */
//	int    length;   /* remaining length of data */
//	int    size;     /* total size of this buffer */
// } datap;

type DataParser struct {
	original *string
	buffer   *string
	length   int
	size     int
}

// BeaconDataExtract Extract a length-prefixed binary blob. The size argument may be NULL.
// If an address is provided, size is populated with the number-of-bytes extracted.
func BeaconDataExtract(datap *DataParser, size *int) *string {
	fmt.Printf("BeaconDataExtract...")
	return nil
}

// BeaconDataInt Extract a 4b integer
func BeaconDataInt(datap *DataParser) {
	fmt.Printf("BeaconDataInt...")
}

// BeaconDataLength Get the amount of data left to parse
func BeaconDataLength(datap *DataParser) int {
	fmt.Printf("BeaconDataLength...")
	return 0
}

// BeaconDataParse Prepare a data parser to extract arguments from the specified buffer
func BeaconDataParse(datap *DataParser, char *string, size int) {
	fmt.Println("BeaconDataParser...")
}

// BeaconDataShort Extract a 2b integer
func BeaconDataShort(datap *DataParser) {
	fmt.Println("BeaconDataShort...")
}

// Output API
// The Output API returns output to Cobalt Strike.
func BeaconPrintf(beaconType int, data uintptr) uintptr {
	fmt.Printf("[BeaconPrintf] BeaconType: %d, Data: %d\n", beaconType, data)
	return 0
}

// BeaconOutput retrieves the output from the executed COFF and prints it to STDOUT
// The function signature is defined by Cobalt Strike's beacon.h
func BeaconOutput(beaconType int, data uintptr, len int) uintptr {
	out := make([]byte, len)
	var readBytes *uintptr

	err := windows.ReadProcessMemory(windows.CurrentProcess(), data, &out[0], uintptr(len), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	fmt.Printf("\n[+] BeaconOutput:\n%s\n", out)
	return 0
}
