package beacon

// https://www.cobaltstrike.com/help-beacon-object-files
// https://www.cobaltstrike.com/downloads/beacon.h

import (
	"C"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	// X-Packages
	"golang.org/x/sys/windows"
)

// Beacon Output API Callback types used with BeaconPrintf and BeaconOutput
const (
	// CALLBACK_OUTPUT is generic output
	// Cobalt Strike will convert this output to UTF-16 (internally) using the target's default character set.
	CALLBACK_OUTPUT = 0x00
	// CALLBACK_OUTPUT_OEM is generic output.
	// Cobalt Strike will convert this output to UTF-16 (internally) using the target's OEM character set.
	// You probably won't need this, unless you're dealing with output from cmd.exe.
	CALLBACK_OUTPUT_OEM = 0x1e
	// CALLBACK_ERROR is a generic error message.
	CALLBACK_ERROR = 0x20
	// CALLBACK_ERROR_OEM is generic output. Cobalt Strike will convert this output to UTF-16 (internally) from UTF-8.
	CALLBACK_ERROR_OEM = 0x0d
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
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

// BeaconDataExtract Extract a length-prefixed binary blob. The size argument may be NULL.
// If an address is provided, size is populated with the number-of-bytes extracted.
// DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);
func BeaconDataExtract(datap *DataParser, size *uint32) uintptr {
	fmt.Printf("[BeaconDataExtract] DataParser@%x - original: 0x%x, buffer: 0x%x, length: %d, size: %d, size: %d\n", datap, datap.original, datap.buffer, datap.length, datap.size, size)
	//fmt.Printf("[BeaconDataExtract] Data: %s\n", windows.UTF16PtrToString((*uint16)(unsafe.Pointer(datap.buffer))))
	if datap.length <= 0 {
		return 0
	}

	// Read the first four bytes to get the size of the data
	dSize := make([]byte, 4)
	var readBytes *uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), datap.buffer, &dSize[0], uintptr(4), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	datap.buffer += uintptr(4)
	datap.length -= 4
	n := binary.LittleEndian.Uint32(dSize)
	fmt.Printf("[BeaconDataExtract] Size: %d\n", n)

	// Read the data from the buffer
	out := make([]byte, n)
	err = windows.ReadProcessMemory(windows.CurrentProcess(), datap.buffer, &out[0], uintptr(n), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	datap.buffer += uintptr(n)
	datap.length -= n
	fmt.Printf("[BeaconDataExtract] Out %x\n", out)
	var s []uint16
	for _, b := range out {
		s = append(s, uint16(b))
	}

	fmt.Printf("[BeaconDataExtract] Returning: '%s'\n", windows.UTF16ToString(s))
	r, err := windows.UTF16PtrFromString(windows.UTF16ToString(s))
	if err != nil {
		fmt.Printf("Error converting string to wide char: %s\n", err)
	}
	// TODO: Refine the way this works because something seems off. Too much conversion.
	// Return the address where the "char*" is pointing to

	return uintptr(unsafe.Pointer(r))
}

// BeaconDataInt Extract a 4b integer
func BeaconDataInt(datap *DataParser) uintptr {
	fmt.Printf("[BeaconDataInt] DataParser@%x - original: 0x%x, buffer: 0x%x, length: %d, size: %d\n", datap, datap.original, datap.buffer, datap.length, datap.size)
	if datap.length < 4 {
		return 0
	}
	// Read four bytes from the buffer and return the 4b integer
	out := make([]byte, datap.length)
	var readBytes *uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), datap.buffer, &out[0], uintptr(datap.length), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	datap.buffer += uintptr(4)
	datap.length -= 4
	fmt.Printf("[BeaconDataInt] Returning %d\n", binary.LittleEndian.Uint32(out))
	return uintptr(binary.LittleEndian.Uint32(out))
}

// BeaconDataLength Get the amount of data left to parse
func BeaconDataLength(datap *DataParser) uintptr {
	fmt.Printf("BeaconDataLength...")
	return 0
}

// BeaconDataParse Prepare a data parser to extract arguments from the specified buffer
func BeaconDataParse(datap *DataParser, buff uintptr, size uint32) uintptr {
	fmt.Printf("[BeaconDataParse] DataParser@%x - original: 0x%x, buffer: 0x%x, length: %d, size: %d; char 0x%x, size: %d\n", datap, datap.original, datap.buffer, datap.length, datap.size, buff, size)
	if size <= 0 {
		return 0
	}
	datap.original = buff
	datap.buffer = buff + uintptr(4)
	datap.length = size - 4
	datap.size = size - 4
	fmt.Printf("[BeaconDataParse] Returning DataParser@%x - original: 0x%x, buffer: 0x%x, length: %d, size: %d\n", datap, datap.original, datap.buffer, datap.length, datap.size)
	return 1
}

// BeaconDataShort Extract a 2b integer
func BeaconDataShort(datap *DataParser) uintptr {
	fmt.Printf("[BeaconDataShort] DataParser - original: 0x%x, buffer: 0x%x, length: %d, size: %d\n", datap.original, datap.buffer, datap.length, datap.size)
	// Read the buffer and return the 2b integer
	if datap.length < 2 {
		return 0
	}

	// Read four bytes from the buffer and return the 4b integer
	out := make([]byte, 2)
	var readBytes *uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), datap.buffer, &out[0], uintptr(datap.length), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	datap.buffer += uintptr(2)
	datap.length -= 2
	fmt.Printf("[BeaconDataShort] Returning %d\n", binary.LittleEndian.Uint16(out))
	return uintptr(binary.LittleEndian.Uint16(out))
}

// BeaconOutput retrieves the output from the executed COFF and prints it to STDOUT
// The function signature is defined by Cobalt Strike's beacon.h
func BeaconOutput(beaconType int, data uintptr, length int) uintptr {
	fmt.Printf("[BeaconOutput] BeaconType: %d, Data: 0x%x, Len: %d\n", beaconType, data, length)
	if length <= 0 {
		fmt.Println("[BeaconOutput] Data length is less than or equal to 0")
		return 0
	}
	out := make([]byte, length)
	var readBytes *uintptr

	err := windows.ReadProcessMemory(windows.CurrentProcess(), data, &out[0], uintptr(length), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	fmt.Printf("\n[+] BeaconOutput:\n%s\n", out)
	return 1
}

// BeaconPrintf formats and presents output to the Beacon operator.
// DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);
// Unable to use variadic function signature because windows.NewCallback does not support it causing a panic.
// panic: compileCallback: argument size is larger than uintptr
func BeaconPrintf(beaconType int, data uintptr, arg0 uintptr, arg1 uintptr, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr, arg6 uintptr, arg7 uintptr, arg8 uintptr, arg9 uintptr) uintptr {
	fmt.Printf("[BeaconPrintf] BeaconType: %d, Data: 0x%x\n", beaconType, data)
	// Read the data from the buffer
	var out []byte
	done := false
	counter := uintptr(0)
	for {
		if done {
			break
		}
		temp := make([]byte, 2)
		var readBytes *uintptr
		err := windows.ReadProcessMemory(windows.CurrentProcess(), data+counter, &temp[0], uintptr(2), readBytes)
		if err != nil {
			fmt.Printf("Error reading process memory: %s\n", err)
		}
		counter += 2
		if temp[0] == 0x0 && temp[1] == 0x0 {
			done = true
		}
		out = append(out, temp...)
	}
	var readBytes *uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), data, &out[0], uintptr(20), readBytes)
	if err != nil {
		fmt.Printf("Error reading process memory: %s\n", err)
	}
	numArgs := strings.Count(string(out), "%")
	//fmt.Printf("[BeaconPrintf] Number of format specifiers: %d\n", numArgs)
	//fmt.Printf("\n[BeaconPrintf] (%d) 0x%x\n", len(out), out)
	fmt.Printf("\n[BeaconPrintf]:\n%s\n", out)

	args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}
	arguments := make([][]byte, numArgs)

	for i, a := range args {
		// Only iterate for the total number of arguments
		if i >= numArgs {
			break
		}
		var arg []byte
		done := false
		counter := uintptr(0)
		for {
			if done {
				break
			}
			temp := make([]byte, 2)
			var readBytes *uintptr
			err := windows.ReadProcessMemory(windows.CurrentProcess(), a+counter, &temp[0], uintptr(2), readBytes)
			if err != nil {
				fmt.Printf("Error reading process memory: %s\n", err)
			}
			counter += 2
			if temp[0] == 0x0 && temp[1] == 0x0 {
				done = true
			}
			arg = append(arg, temp...)
		}
		//fmt.Printf("\n[BeaconPrintf] Argument %d: '%s' at 0x%x - (%d) 0x%x\n", i, arg, a, len(arg), arg)
		arguments[i] = arg
	}

	loop := 0
	for {
		if loop >= numArgs {
			break
		}
		for i, b := range out {
			var f []byte
			if b == '%' {
				f = make([]byte, 2)
				f[0] = out[i]
				f[1] = out[i+1]
			}
			if f != nil {
				before, after, found := bytes.Cut(out, f)
				if found {
					z := make([]byte, len(before))
					z = append(z, before...)
					z = append(z, arguments[loop]...)
					z = append(z, after...)
					out = make([]byte, len(z))
					copy(out, z)
					loop++
					break
				}
			}
		}
	}
	fmt.Printf("\n[BeaconPrintf] Returning:\n%s\n", out)
	return 0
}

// BOFPack packs each item in the string slice according to their prefixed data type and returns the packed data
// b - binary data
// i - 4-byte integer
// s - 2-byte short integer
// z - zero-terminated+encoded string
// Z - zero-terminated wide-char string
// Call BOFPackBinary, BOFPackInt, BOFPackShort, BOFPackString, or BOFPackStringWide if you already know the data type
func BOFPack(data []string) ([]byte, error) {
	// If there are no arguments, return nil
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		if len(arg) < 2 {
			return nil, fmt.Errorf("[BOFPack] the argument '%s' is not valid", arg)
		}
		switch arg[0] {
		case 'b':
			// b - binary data
			data, err := BOFPackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the binary data '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'i':
			// i - 4-byte integer
			data, err := BOFPackIntString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the integer '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 's':
			// s - 2-byte short integer
			data, err := BOFPackShortString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the short integer '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'z':
			// z - zero-terminated+encoded string
			data, err := BOFPackString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the string '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'Z':
			// Z - zero-terminated wide-char string
			data, err := BOFPackWideString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the wide string '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		default:
			return nil, fmt.Errorf("[BOFPack] the data type prefix '%s' in '%s' is not valid, try 'b', 'i', 's','z', or 'Z'", string(arg[0]), arg)
		}
	}
	// Prefix the buffer with its size
	rData := make([]byte, 4)
	binary.LittleEndian.PutUint32(rData, uint32(len(buff)))
	// Append the buffer
	rData = append(rData, buff...)
	fmt.Printf("[BOFPack] Returning packed BOF buffer of size %d: %x\n", len(rData), rData)
	return rData, nil
}

// BOFPackCSV parse a string of comma-separated values, prefixed with their data type, and packs them into a byte slice
func BOFPackCSV(data string) ([]byte, error) {
	return BOFPack(strings.Split(data, ","))
}

// BOFPackBinary hex decodes the string and packs binary data into a byte slice
// Used with the BeaconData C API's 'b' data type and unpacked with BeaconDataExtract
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackBinary(data string) ([]byte, error) {
	hexData, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackBinary] there was an error hex decoding the string '%s': %s", data, err)
	}
	return hexData, nil
}

// BOFPackInt packs a 4-byte unsigned integer into a byte slice
// Used with the BeaconData C API's 'i' data type and unpacked with BeaconDataInt
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackInt(i uint32) ([]byte, error) {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(i))
	return buff, nil
}

// BOFPackIntString converts the string to an unsigned 4-byte integer and packs it into a byte slice
// Used with the BeaconData C API's 's' data type and unpacked with BeaconDataInt
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackIntString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackIntString] there was an error converting the string '%s' to an integer: %s", s, err)
	}
	return BOFPackInt(uint32(i))
}

// BOFPackShort packs a 2-byte unsigned integer into a byte slice
// Used with the BeaconData C API's 's' data type and unpacked with BeaconDataShort
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackShort(i uint16) ([]byte, error) {
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(i))
	return buff, nil
}

// BOFPackShortString converts the string to an unsigned 2-byte integer and packs it into a byte slice
// Used with the BeaconData C API's 's' data type and unpacked with BeaconDataShort
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackShortString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackShortString] there was an error converting the string '%s' to an integer: %s", s, err)
	}
	return BOFPackShort(uint16(i))
}

// BOFPackString converts the string to a zero-terminated+encoded string and packs it into a byte slice
// Used with the BeaconData C API's 'z' data type and unpacked with BeaconDataExtract
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackString(s string) ([]byte, error) {
	d, err := windows.UTF16FromString(s)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackString] there was an error converting the string '%s' to UTF16: %s", s, err)
	}
	buff := make([]byte, 4)
	// Prefix the data size
	binary.LittleEndian.PutUint32(buff, uint32(len(d)))
	for _, c := range d {
		buff = append(buff, byte(c))
	}
	return buff, nil
}

// BOFPackWideString converts the string to a zero-terminated wide-char string and packs it into a byte slice
// BOFPackString converts the string to a zero-terminated+encoded string and packs it into a byte slice
// Used with the BeaconData C API's 'Z' data type and unpacked with BeaconDataExtract
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
func BOFPackWideString(s string) ([]byte, error) {
	d, err := windows.UTF16FromString(s)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackWideString] there was an error converting the string '%s' to UTF16: %s", s, err)
	}
	buff := make([]byte, 4)
	// Prefix the data size
	binary.LittleEndian.PutUint32(buff, uint32(len(d)))
	for _, c := range d {
		buff = append(buff, byte(c))
	}
	return buff, nil
}
