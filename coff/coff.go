// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

package coff

import (
	// Standard
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	// X-Packages
	"golang.org/x/sys/windows"

	// Internal
	"github.com/Ne0nd0g/go-coff/coff/beacon"
)

var Verbose bool
var Debug bool

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var ntdll = windows.NewLazySystemDLL("ntdll.dll")
var RtlCopyMemory = ntdll.NewProc("RtlCopyMemory")
var sectionAddress []uintptr

// AMD64
const (
	IMAGE_REL_AMD64_ABSOLUTE = 0x0000
	IMAGE_REL_AMD64_ADDR64   = 0x0001
	IMAGE_REL_AMD64_ADDR32   = 0x0002
	// IMAGE_REL_AMD64_ADDR32NB The 32-bit address without an image base (RVA).
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	// IMAGE_REL_AMD64_REL32 The 32-bit relative address from the byte following the relocation.
	IMAGE_REL_AMD64_REL32   = 0x0004
	IMAGE_REL_AMD64_REL32_1 = 0x0005
	IMAGE_REL_AMD64_REL32_2 = 0x0006
	IMAGE_REL_AMD64_REL32_3 = 0x0007
	IMAGE_REL_AMD64_REL32_4 = 0x0008
	IMAGE_REL_AMD64_REL32_5 = 0x0009
	IMAGE_REL_AMD64_SECTION = 0x000A
	IMAGE_REL_AMD64_SECREL  = 0x000B
	IMAGE_REL_AMD64_SECREL7 = 0x000C
	IMAGE_REL_AMD64_TOKEN   = 0x000D
	IMAGE_REL_AMD64_SREL32  = 0x000E
	IMAGE_REL_AMD64_PAIR    = 0x000F
	IMAGE_REL_AMD64_SSPAN32 = 0x0010
)

// i386
const (
	IMAGE_REL_I386_ABSOLUTE = 0x0000
	IMAGE_REL_I386_DIR16    = 0x0001
	IMAGE_REL_I386_REL16    = 0x0002
	IMAGE_REL_I386_DIR32    = 0x0006
	IMAGE_REL_I386_DIR32NB  = 0x0007
	IMAGE_REL_I386_SEG12    = 0x0009
	IMAGE_REL_I386_SECTION  = 0x000A
	IMAGE_REL_I386_SECREL   = 0x000B
	IMAGE_REL_I386_TOKEN    = 0x000C
	IMAGE_REL_I386_SECREL7  = 0x000D
	IMAGE_REL_I386_REL32    = 0x0014
)

// Section Characteristic Flags
const (
	IMAGE_SCN_MEM_WRITE              = 0x80000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
)

// Machine Types
const (
	IMAGE_FILE_MACHINE_AMD64 = 0x8664 // x64
)

const (
	SIZE_SYMBOL         = 18
	SIZE_RELOCATION     = 10
	SIZE_SECTION_HEADER = 40
)

// Storage Class https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#storage-class
const (
	// IMAGE_SYM_CLASS_EXTERNAL A value that Microsoft tools use for external symbols.
	// The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0).
	// If the section number is not zero, then the Value field specifies the offset within the section.
	IMAGE_SYM_CLASS_EXTERNAL = 2
	// IMAGE_SYM_CLASS_STATIC The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
	IMAGE_SYM_CLASS_STATIC = 3
)

// Memory Allocation
const (
	// MEM_COMMIT Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved memory pages.
	// The function also guarantees that when the caller later initially accesses the memory, the contents will be zero.
	// Actual physical pages are not allocated unless/until the virtual addresses are actually accessed.
	MEM_COMMIT = 0x1000
	// MEM_RESERVE Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in the paging file on disk.
	// You can commit reserved pages in subsequent calls to the VirtualAlloc function.
	MEM_RESERVE = 0x2000
	// MEM_RELEASE Releases the specified region of pages, or placeholder (for a placeholder, the address space is released and available for other allocations).
	// After this operation, the pages are in the free state.
	MEM_RELEASE = 0x8000
)

// Memory Protection Constants
// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
const (
	// PAGE_EXECUTE Enables execute access to the committed region of pages. An attempt to write to the committed region results in an access violation.
	PAGE_EXECUTE = 0x10
	// PAGE_EXECUTE_READ Enables execute or read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation.
	PAGE_EXECUTE_READ = 0x20
	// PAGE_EXECUTE_READWRITE Enables execute, read-only, or read/write access to the committed region of pages.
	PAGE_EXECUTE_READWRITE = 0x40
	// PAGE_READWRITE Enables read-only or read/write access to the committed region of pages.
	// If Data Execution Prevention is enabled, attempting to execute code in the committed region results in an access violation.
	PAGE_READWRITE = 0x04
)

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
// Length: 20
type FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
//
//	typedef struct _IMAGE_SECTION_HEADER {
//	 BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
//	 union {
//	   DWORD PhysicalAddress;
//	   DWORD VirtualSize;
//	 } Misc;
//	 DWORD VirtualAddress;
//	 DWORD SizeOfRawData;
//	 DWORD PointerToRawData;
//	 DWORD PointerToRelocations;
//	 DWORD PointerToLinenumbers;
//	 WORD  NumberOfRelocations;
//	 WORD  NumberOfLinenumbers;
//	 DWORD Characteristics;
//	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
//
// Length: 40
type SECTION_HEADER struct {
	// Name is an 8-byte, null-padded UTF-8 string.
	// There is no terminating null character if the string is exactly eight characters long.
	// For longer names, this member contains a forward slash (/) followed by an ASCII representation of a decimal number that is an offset into the string table.
	// Executable images do not use a string table and do not support section names longer than eight characters.
	Name [8]byte
	// Misc is a union of two DWORD structures: PhysicalAddress and VirtualSize.
	// Misc.PhysicalAddress is the file address.
	// Misc.VirtualSize The total size of the section when loaded into memory, in bytes.
	// If this value is greater than the SizeOfRawData member, the section is filled with zeroes.
	// This field is valid only for executable images and should be set to 0 for object files.
	// The total size of the section when loaded into memory.
	// If this value is greater than SizeOfRawData, the section is zero-padded.
	// This field is valid only for executable images and should be set to zero for object files.
	VirtualSize uint32
	// VirtualAddress is the address of the first byte of the section when loaded into memory, relative to the image base.
	// For object files, this is the address of the first byte before relocation is applied.
	VirtualAddress uint32
	// SizeOfRawData is the size of the initialized data on disk, in bytes.
	// This value must be a multiple of the FileAlignment member of the IMAGE_OPTIONAL_HEADER structure.
	// If this value is less than the VirtualSize member, the remainder of the section is filled with zeroes.
	// If the section contains only uninitialized data, the member is zero.
	SizeOfRawData uint32
	// PointerToRawData is the file pointer to the first page of the section within the COFF file.
	// For executable images, this must be a multiple of FileAlignment from the optional header.
	// For object files, the value should be aligned on a 4-byte boundary for the best performance.
	// When a section contains only uninitialized data, this field should be zero.
	PointerToRawData uint32
	// PointerToRelocations is the file pointer to the beginning of relocation entries for the section.
	// This is set to zero for executable images or if there are no relocations.
	PointerToRelocations uint32
	// PointerToLinenumbers is the file pointer to the beginning of line-number entries for the section.
	// This is set to zero if there are no COFF line numbers.
	// This value should be zero for an image because COFF debugging information is deprecated.
	PointerToLinenumbers uint32
	// NumberOfRelocations is the number of relocation entries for the section. This is set to zero for executable images.
	NumberOfRelocations uint16
	// NumberOfLinenumbers is the number of line-number entries for the section.
	// This value should be zero for an image because COFF debugging information is deprecated.
	NumberOfLinenumbers uint16
	// Characteristics is the flags that describe the characteristics of the section.
	// See the Section Characteristic Flags constants IMAGE_SCN_*
	Characteristics uint32
}

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
// Length: 10
// Due to padding, unsafe.Sizeof() reports 12
type RELOCATION struct {
	// VirtualAddress is the address of the item to which relocation is applied.
	// This is the offset from the beginning of the section, plus the value of the section's RVA/Offset field. See Section Table (Section Headers).
	// For example, if the first byte of the section has an address of 0x10, the third byte has an address of 0x12.
	VirtualAddress uint32
	// SymbolTableIndex A zero-based index into the symbol table.
	// This symbol gives the address that is to be used for the relocation.
	// If the specified symbol has section storage class, then the symbol's address is the address with the first section of the same name.
	SymbolTableIndex uint32
	// Type A value that indicates the kind of relocation that should be performed.
	// Valid relocation types depend on the machine type.
	Type uint16
}

// SYMBOL represents a COFF symbol table entry
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
// Length: 18
// Due to padding, unsafe.Sizeof() reports 20 https://dave.cheney.net/2015/10/09/padding-is-hard
type SYMBOL struct {
	// Name The name of the symbol, represented by a union of three structures. An array of 8 bytes is used if the name is not more than 8 bytes long.
	Name [8]byte
	// Value The value that is associated with the symbol. The interpretation of this field depends on SectionNumber and StorageClass.
	// A typical meaning is the relocatable address.
	Value uint32
	// SectionNumber The signed integer that identifies the section, using a one-based index into the section table.
	// Some values have special meaning, as defined in section 5.4.2, "Section Number Values."
	SectionNumber uint16
	// Type A number that represents type. Microsoft tools set this field to 0x20 (function) or 0x0 (not a function).
	Type uint16
	// StorageClass An enumerated value that represents storage class.
	StorageClass uint8
	// NumberOfAuxSymbols The number of auxiliary symbol table entries that follow this record.
	NumberOfAuxSymbols uint8
	//_                  [2]byte // Go optimized padding :0)
}

type OBJECT struct {
	Header   FILE_HEADER
	Sections []SECTION
	Symbols  []SYMBOL
	Strings  []byte // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-string-table
}

type SECTION struct {
	Header      SECTION_HEADER
	Relocations []RELOCATION
	Data        []byte
}

// Parse reads in an object file as bytes and parses it into a COFF Object
func ParseObject(data []byte) (object OBJECT, err error) {

	// Read in the COFF File Header
	if Verbose {
		fmt.Printf("[-] Parsing file header...\n")
	}

	err = binary.Read(bytes.NewBuffer(data[:unsafe.Sizeof(object.Header)]), binary.LittleEndian, &object.Header)
	if err != nil {
		return
	}

	if Debug {
		fmt.Printf("[DEBUG] COFF_FILE_HEADER(%d): %+v\n", unsafe.Sizeof(object.Header), object.Header)
	}

	// Validate that the object is for a x64 host
	if object.Header.Machine != IMAGE_FILE_MACHINE_AMD64 {
		err = fmt.Errorf("the object file was for a 0x%x host but must be %x", object.Header.Machine, IMAGE_FILE_MACHINE_AMD64)
		return
	}

	// Validate that file is an OBJECT and not an IMAGE
	if object.Header.SizeOfOptionalHeader != 0 {
		err = fmt.Errorf("the object contained an optional header of size %d; Object files should not have this header", object.Header.SizeOfOptionalHeader)
		return
	}

	// Read in Sections
	if Verbose {
		fmt.Printf("[-] Parsing Sections...\n")
	}

	for i := 0; i < int(object.Header.NumberOfSections); i++ {
		var section SECTION
		// Position of the section header relative to the file header * section number
		start := unsafe.Sizeof(object.Header) + (unsafe.Sizeof(SECTION_HEADER{}) * uintptr(i))
		stop := start + unsafe.Sizeof(SECTION_HEADER{})
		err = binary.Read(bytes.NewBuffer(data[start:stop]), binary.LittleEndian, &section.Header)
		if err != nil {
			return
		}

		object.Sections = append(object.Sections, section)
		if Debug {
			//name := make([]byte, 8)
			//binary.LittleEndian.PutUint64(name, section.Header.Name)
			//fmt.Println(fmt.Sprintf("[DEBUG] Section (%d) %s: %+v", i, name, section))
			fmt.Printf("[DEBUG] Section (%d) %s:%+v\n", i, section.Header.Name, section.Header)
		}

	}

	if Debug {
		fmt.Printf("[DEBUG] Sections(%d): %+v\n", len(object.Sections), object.Sections)
	}

	// Read in String Table
	if Verbose {
		fmt.Println("[-] Parsing Strings Table...")
	}

	// Immediately following the COFF symbol table is the COFF string table.
	// The position of this table is found by taking the symbol table address in
	// the COFF header and adding the number of symbols multiplied by the size of a symbol.
	pointerToStringTable := object.Header.PointerToSymbolTable + (object.Header.NumberOfSymbols * SIZE_SYMBOL)

	// At the beginning of the COFF string table are 4 bytes that contain the total size (in bytes) of the rest of the string table. This size includes
	// the size field itself, so that the value in this location would be 4 if no strings were present.
	sizeOfStringTable := binary.LittleEndian.Uint32(data[pointerToStringTable:(pointerToStringTable + 4)])

	// Start past the 4 bytes that contain the String Table size
	object.Strings = data[pointerToStringTable : pointerToStringTable+sizeOfStringTable]

	if Debug {
		fmt.Printf("[DEBUG] PointerToStringTable: %d\n", pointerToStringTable)
		fmt.Printf("[DEBUG] Strings Table (%d):\n%s\n", binary.LittleEndian.Uint32(data[pointerToStringTable:pointerToStringTable+4]), object.Strings)
	}

	// Read in Relocations
	if Verbose {
		fmt.Println("[-] Parsing Section Relocations and Data...")
	}

	for s, section := range object.Sections {
		//name := make([]byte, 8)
		//binary.LittleEndian.PutUint64(name, section.Header.Name)
		// Make sure there are relocations to process
		if section.Header.NumberOfRelocations > 0 {
			if Verbose {
				fmt.Printf("[-] Parsing %d relocations for %s section...\n", section.Header.NumberOfRelocations, object.SectionHeaderName(section.Header.Name))
			}
			for i := 0; i < int(section.Header.NumberOfRelocations); i++ {
				var relocation RELOCATION
				start := section.Header.PointerToRelocations + uint32(SIZE_RELOCATION*i)
				stop := start + uint32(SIZE_RELOCATION)
				err = binary.Read(bytes.NewBuffer(data[start:stop]), binary.LittleEndian, &relocation)
				if err != nil {
					return
				}
				object.Sections[s].Relocations = append(object.Sections[s].Relocations, relocation)

				if Debug {
					fmt.Printf("\t[DEBUG] Relocation: %+v\n", relocation)
				}
			}
		}
		// Section Data
		if Verbose {
			fmt.Printf("[-] Parsing %s Section Data %d-bytes\n", object.SectionHeaderName(section.Header.Name), section.Header.SizeOfRawData)
		}
		object.Sections[s].Data = data[section.Header.PointerToRawData : section.Header.PointerToRawData+section.Header.SizeOfRawData]
	}

	// Read in Symbols
	if Verbose {
		fmt.Println("[-] Parsing Symbols...")
	}
	if Debug {
		fmt.Printf("[DEBUG] PointerToSymbolTable: %d\n", object.Header.PointerToSymbolTable)
	}

	for i := 0; i < int(object.Header.NumberOfSymbols); i++ {
		var symbol SYMBOL
		start := object.Header.PointerToSymbolTable + (uint32(18) * uint32(i))
		stop := start + uint32(18)
		if Debug {
			fmt.Printf("[DEBUG] Start: %d, Stop: %d, Bytes: %v\n", start, stop, data[start:stop])
		}
		err = binary.Read(bytes.NewBuffer(data[start:stop]), binary.LittleEndian, &symbol)
		if err != nil {
			fmt.Println("There was a problem reading the bytes")
			return
		}
		object.Symbols = append(object.Symbols, symbol)
		if Debug {
			fmt.Printf("[DEBUG] Symbol (%s): %+v\n", symbol.String(object.Strings), symbol)
		}
	}
	return
}

// Load maps the Object into memory and applies relocations
func (object *OBJECT) Load() error {
	// Windows API functions
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")

	sectionAddress = make([]uintptr, object.Header.NumberOfSections)

	// Global Offset Table
	var got unsafe.Pointer
	gotCounter := 0

	// Sections
	for sectionIndex, section := range object.Sections {
		if section.Header.SizeOfRawData > 0 {
			// Allocate memory for the section
			if Verbose {
				fmt.Printf("\n[-] Allocating memory for %s section of size %d...\n", object.SectionHeaderName(section.Header.Name), section.Header.SizeOfRawData)
			}

			addr, _, err := VirtualAlloc.Call(0, uintptr(section.Header.SizeOfRawData), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

			if !errors.Is(err, syscall.Errno(0)) {
				return fmt.Errorf("there was an error calling VirtualAlloc: %s", err)
			}

			if addr == 0 {
				return fmt.Errorf("VirtualAlloc failed and returned 0")
			}

			sectionAddress[sectionIndex] = addr

			if Debug {
				fmt.Printf("[DEBUG] Allocated memory for %s at 0x%x\n", object.SectionHeaderName(section.Header.Name), addr)
			}

			// Copy the section data to the allocated memory segment
			if Verbose {
				fmt.Printf("[-] Copying %s section data of size %d to allocated memory address 0x%x\n", object.SectionHeaderName(section.Header.Name), uintptr(section.Header.SizeOfRawData), addr)
			}
			_, _, err = RtlCopyMemory.Call(addr, uintptr(unsafe.Pointer(&section.Data[0])), uintptr(section.Header.SizeOfRawData))

			if !errors.Is(err, syscall.Errno(0)) {
				return fmt.Errorf("error calling RtlCopyMemory: %s", err)
			}
		} else {
			if Verbose {
				fmt.Printf("\n[-] Skipping memory allocation of %s section of size %d\n", object.SectionHeaderName(section.Header.Name), section.Header.SizeOfRawData)
			}
		}
	}

	// Create the Global Offset Table
	addr, _, err := VirtualAlloc.Call(0, uintptr(2048), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if !errors.Is(err, syscall.Errno(0)) {
		return fmt.Errorf("there was an error calling VirtualAlloc: %s", err)
	}
	got = unsafe.Pointer(addr)

	if Verbose {
		fmt.Printf("\n[-] Allocated memory for GOT at 0x%x\n", addr)
	}

	// Now that the sections are mapped to memory, execute relocations
	for sectionIndex, section := range object.Sections {
		if section.Header.NumberOfRelocations <= 0 {
			continue
		}
		if Verbose {
			fmt.Printf("\n[-] Applying %d relocations for %s section...\n", section.Header.NumberOfRelocations, object.SectionHeaderName(section.Header.Name))
		}

		if Debug {
			fmt.Printf("[DEBUG] Section: %+v\n", section.Header)
		}

		// Relocations
		for _, relocation := range section.Relocations {
			symbol := object.Symbols[relocation.SymbolTableIndex]
			symbolName := symbol.String(object.Strings)
			if Debug {
				fmt.Printf("\n[DEBUG] Relocation record for %s section: %+v\n", object.SectionHeaderName(section.Header.Name), relocation)
				fmt.Printf("\t[DEBUG] Relocation symbol record (%s): %+v\n", symbolName, symbol)
			}

			var addr uintptr
			var err error

			// Parse Symbols
			switch symbol.StorageClass {
			case IMAGE_SYM_CLASS_EXTERNAL:
				if strings.HasPrefix(symbolName, "__imp_") {
					s := strings.Split(strings.TrimPrefix(symbolName, "__imp_"), "$")
					var module string
					var proc string
					if len(s) > 0 {
						module = s[0]
					}
					if len(s) > 1 {
						proc = s[1]
					}
					if Verbose {
						fmt.Printf("\t[-] Importing External Module: %s, Procedure: %s\n", module, proc)
					}
					if strings.HasPrefix(module, "Beacon") {
						addr, err = beaconFunction(module)
						if err != nil {
							log.Fatal(err)
						}
					}
					// External Procedure
					if proc != "" {
						addr, err = getProcAddress(module, proc)
						if err != nil {
							log.Fatal(err)
						}
					}
					// Destination, Source, Length
					x := int64(addr)
					y := uintptr(unsafe.Pointer(&x))
					if Debug {
						fmt.Printf("\t[DEBUG] Global Offset Table: writing 0x%x to 0x%x for %s!%s at pointer 0x%x\n", x, uintptr(got)+uintptr(gotCounter*8), module, proc, y)
					}
					_, _, err = RtlCopyMemory.Call(uintptr(got)+uintptr(gotCounter*8), y, 8)

					if !errors.Is(err, syscall.Errno(0)) {
						return fmt.Errorf("there was an error calling RtlCopyMemory: %s", err)
					}
					addr = uintptr(got) + uintptr(gotCounter*8)
					gotCounter++
				}
			// IMAGE_SYM_CLASS_STATIC is the offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
			case IMAGE_SYM_CLASS_STATIC:
				if len(sectionAddress) <= int(symbol.SectionNumber) {
					log.Fatalf("unable to perform relocation because section %d has not been mapped into memory", symbol.SectionNumber)
				}
				if Debug {
					fmt.Printf("\t[DEBUG] Symbol name: %s, Symbol StorageClass: IMAGE_SYM_CLASS_STATIC(0x%d) at 0x%x\n", symbolName, symbol.StorageClass, sectionAddress[symbol.SectionNumber-1])
					if symbol.NumberOfAuxSymbols > 0 {
						fmt.Printf("\t[DEBUG] Next symbol record: %+v\n", object.Symbols[relocation.SymbolTableIndex+1])
					}
				}

				// Get the symbol offset value from the current section;
				offsetBytes := make([]byte, 4)
				copy(offsetBytes, object.Sections[sectionIndex].Data[relocation.VirtualAddress:relocation.VirtualAddress+4])
				if Debug {
					fmt.Printf("\t[DEBUG] Relocation's VirtualAddress contents: %v\n", offsetBytes)
				}
				// Honestly not sure how to use this "offset" value, going to just add it to the symbol section table for now
				offset := binary.LittleEndian.Uint32(offsetBytes)

				if symbol.Value == 0 {
					addr = sectionAddress[object.Symbols[relocation.SymbolTableIndex].SectionNumber-1] + uintptr(offset)
				} else {
					log.Fatal("The code required to handle a symbol with a value other than zero for the IMAGE_SYM_CLASS_STATIC class is missing...")
				}
			default:
				log.Fatalf("unhandled symbol storge class %d", symbol.StorageClass)
			}
			// Do relocation
			err = object.relocate(sectionIndex, relocation, addr)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Run executes the provided COFF function
func (object *OBJECT) Run(entrypoint string, args uintptr, length uint64) error {
	if Verbose {
		fmt.Printf("[-] Executing the COFF '%s'function...\n", entrypoint)
	}

	// Execute the function
	var functionAddr uintptr
	// Find the function address
	for _, symbol := range object.Symbols {
		//fmt.Printf("Symbol: %+v, %s:%v\n", symbol, symbol.String(object.Strings), symbol.Name)
		if symbol.Name == [8]byte{103, 111, 0, 0, 0, 0, 0, 0} {
			functionAddr = sectionAddress[symbol.SectionNumber-1] + uintptr(symbol.Value)
			if Debug {
				fmt.Printf("[DEBUG] Found the go function at: 0x%x\n", functionAddr)
			}
		}
	}

	if functionAddr == 0 {
		return fmt.Errorf("unable to find the entrypoint function: %s", entrypoint)
	}

	if Debug {
		fmt.Printf("[DEBUG] Executing the '%s' function at 0x%0X...\n", entrypoint, functionAddr)
		fmt.Println("[DEBUG] Press Enter to continue...")
		fmt.Scanln()
	}

	r, _, err := syscall.SyscallN(functionAddr, args, uintptr(length))

	if !errors.Is(err, syscall.Errno(0)) {
		return fmt.Errorf("there was an error calling the entrypoint function: %s", err)
	}
	if Debug {
		fmt.Printf("[DEBUG] Executing the entrypoint function returned: %d\n", r)
	}
	return nil
}

// relocate applies the relocation to the section
func (object *OBJECT) relocate(section int, relocation RELOCATION, symbol uintptr) error {
	if Debug {
		fmt.Printf("\t[DEBUG] Relocating section %d with relocation record: %+v to symbol pointer: 0x%x\n", section, relocation, symbol)
	}

	// Make sure the section has already been mapped into memory
	if len(sectionAddress) <= section {
		return fmt.Errorf("unable to perform relocation because section %d has not been mapped into memory", section)
	}

	switch relocation.Type {
	case IMAGE_REL_AMD64_ADDR32NB:
		// IMAGE_REL_AMD64_ADDR32NB is the 32-bit address without an image base (RVA).
		// TODO: Actually implement this
		if Debug {
			fmt.Printf("\t[DEBUG] Handling relocation for IMAGE_REL_AMD64_ADDR32NB storage class with symbol: 0x%x\n", symbol)
		}
		switch object.Symbols[relocation.SymbolTableIndex].StorageClass {
		case IMAGE_SYM_CLASS_STATIC:
			if Verbose {
				fmt.Printf("\t[*] IMAGE_SYM_CLASS_STATIC: VA: 0x%x - Symbol 0x%x = 0x%x\n", uint32(sectionAddress[section])+relocation.VirtualAddress, symbol, (uint32(sectionAddress[section])+relocation.VirtualAddress)-uint32(symbol))
			}
		}
	case IMAGE_REL_AMD64_REL32:
		// IMAGE_REL_AMD64_REL32 is the 32-bit relative address from the byte following the relocation.
		// Copy the 32-bit address of the symbol to the section + relocation relative address
		if Debug {
			fmt.Printf("\t[DEBUG] Handling relocation for IMAGE_REL_AMD64_REL32 storage class with symbol: 0x%x\n", symbol)
		}
		relative := make([]byte, 4)

		switch object.Symbols[relocation.SymbolTableIndex].StorageClass {
		case IMAGE_SYM_CLASS_EXTERNAL:
			if Verbose {
				fmt.Printf("\t[*] IMAGE_SYM_CLASS_EXTERNAL: VA: 0x%x - Symbol 0x%x = 0x%x\n", uint32(sectionAddress[section])+relocation.VirtualAddress, symbol, (uint32(sectionAddress[section])+relocation.VirtualAddress)-uint32(symbol))
			}
			binary.LittleEndian.PutUint32(relative, uint32(symbol)-(uint32(sectionAddress[section])+relocation.VirtualAddress+4))
		case IMAGE_SYM_CLASS_STATIC:
			// ([Symbol Section Address] + [RVA contents]) - [Relocation VA +4]
			binary.LittleEndian.PutUint32(relative, uint32(symbol)-(uint32(sectionAddress[section])+(relocation.VirtualAddress+4)))
		}
		destination := sectionAddress[section] + uintptr(relocation.VirtualAddress)
		source := unsafe.Pointer(&relative[0])
		if Debug {
			fmt.Printf("\t[DEBUG] Calling RtlCopyMemory with 0x%x, 0x%x, 4\n", destination, relative)
		}
		// Destination, Source, Length
		_, _, err := RtlCopyMemory.Call(destination, uintptr(source), 4)

		if !errors.Is(err, syscall.Errno(0)) {
			return fmt.Errorf("there was an error calling RtlCopyMemory: %s", err)
		}
	default:
		return fmt.Errorf("unhandled relocation type: %d", relocation.Type)
	}
	return nil
}

// SectionHeaderName returns the name of the section from the Section Header
// If the first byte of the section name is "/" (0x2F), the name is longer than 8 bytes and the name is an offset into the String Table
func (object *OBJECT) SectionHeaderName(name [8]byte) string {
	if name[0] == 0x2F {
		offset, err := strconv.Atoi(string(bytes.Split(name[1:], []byte{0x00})[0]))
		if err != nil {
			fmt.Printf("there was a problem converting the section name '%s' to an integer: %s\n", name[1:], err)
		}
		if len(object.Strings) < offset {
			return ""
		}
		return string(bytes.Split(object.Strings[offset:], []byte{0x00})[0])
	}
	return string(bytes.Trim(name[:], "\x00"))
}

// getProcAddress returns the address of the specified procedure in the specified module
// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
func getProcAddress(module, proc string) (uintptr, error) {
	hModule, err := loadLibrary(module)
	if err != nil {
		return hModule, err
	}
	GetProcAddress := kernel32.NewProc("GetProcAddress")

	if Verbose {
		fmt.Printf("\t[-] Calling Kernel32 GetProcAddress for %s!%s...\n", module, proc)
	}
	FARPROC, _, err := GetProcAddress.Call(hModule, uintptr(unsafe.Pointer(&[]byte(proc)[0])))
	if !errors.Is(err, syscall.Errno(0)) {
		return FARPROC, fmt.Errorf("there was an error getting the %s!%s procedure: %s", module, proc, err)
	}
	if Debug {
		fmt.Printf("\t[DEBUG] %s!%s address: 0x%x\n", module, proc, FARPROC)
	}
	return FARPROC, nil
}

// loadLibrary loads the specified module into the address space of the calling process
// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
func loadLibrary(module string) (uintptr, error) {
	// Kernel32 is already loaded
	if strings.ToLower(module) == "kernel32" {
		return kernel32.Handle(), nil
	}

	LoadLibrary := kernel32.NewProc("LoadLibraryA")
	mod := append([]byte(module), 0)

	if Verbose {
		fmt.Printf("\t[-] Calling LoadLibraryA for %s\n", module)
	}
	hModule, _, err := LoadLibrary.Call(uintptr(unsafe.Pointer(&mod[0])))
	if !errors.Is(err, syscall.Errno(0)) {
		return hModule, fmt.Errorf("there was an error calling LoadLibraryA for %s: %s", module, err)
	}

	if Debug {
		fmt.Printf("\t[DEBUG] %s handle: 0x%x\n", module, hModule)
	}

	return hModule, nil
}

// String evaluates the first four bytes of the Symbol Name to determine where it's full name can be found and returns the Symbol Name as a string
func (symbol *SYMBOL) String(table []byte) string {
	// To determine whether the name itself or an offset is given, test the first 4 bytes for equality to zero.
	if binary.LittleEndian.Uint32(symbol.Name[0:4]) == 0 {
		// The Symbol name is longer than 8 bytes
		start := binary.LittleEndian.Uint32(symbol.Name[4:8])
		//fmt.Println(fmt.Sprintf("\t[DEBUG] Symbol Name String Table Offset: %d", start))
		return string(bytes.Split(table[start:], []byte{0x00})[0])
	}
	// Does not require the String Table
	name := make([]byte, 8)
	binary.LittleEndian.PutUint64(name, binary.LittleEndian.Uint64(symbol.Name[:]))
	return string(name)
}

// beaconFunction returns the address of the Beacon API function from this program
func beaconFunction(function string) (addr uintptr, err error) {
	if Verbose {
		fmt.Printf("\t[-] Resolving Beacon API function: %s...\n", function)
	}

	switch function {
	case "BeaconDataExtract":
		addr = windows.NewCallback(beacon.BeaconDataExtract)
	case "BeaconDataParse":
		addr = windows.NewCallback(beacon.BeaconDataParse)
	case "BeaconOutput":
		addr = windows.NewCallback(beacon.BeaconOutput)
	case "BeaconPrintf":
		addr = windows.NewCallback(beacon.BeaconPrintf)
	default:
		err = fmt.Errorf("unable to resolve Beacon API function %s", function)
		return
	}
	if Debug {
		fmt.Printf("\t[DEBUG] '%s' function at 0x%x\n", function, addr)
	}
	return
}
