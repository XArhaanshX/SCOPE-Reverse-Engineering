//go:build windows

// Windows removable-drive enumeration for the licence check. Reconstructed from
// GetUSBCandidates / getVolumeInfo / getDriveSize in the unpacked image, which
// call GetLogicalDrives, GetDriveTypeW, GetVolumeInformationW and
// GetDiskFreeSpaceExW out of kernel32.dll.
package lock

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDrives  = kernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW     = kernel32.NewProc("GetDriveTypeW")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW   = kernel32.NewProc("GetDiskFreeSpaceExW")
)

const driveRemovable = 2 // DRIVE_REMOVABLE

// GetUSBCandidates returns one USBInfo for each removable drive currently
// attached. It returns an error when no removable drive is present (the
// "no licensed USB drive was detected" case in main).
func GetUSBCandidates() ([]USBInfo, error) {
	mask, _, _ := procGetLogicalDrives.Call()
	var out []USBInfo
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+i)
		rootPtr, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		dtype, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(rootPtr)))
		if dtype != driveRemovable {
			continue
		}
		label, serial, err := getVolumeInfo(root)
		if err != nil {
			continue
		}
		size, err := getDriveSize(root)
		if err != nil {
			continue
		}
		a, b, c, err := getDeviceInfo(root)
		if err != nil {
			continue
		}
		out = append(out, USBInfo{A: a, B: b, C: c, Label: label, Serial: serial, Size: size, Root: root})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no removable drives found")
	}
	return out, nil
}

// getVolumeInfo returns the volume label and the volume serial formatted as
// eight uppercase hex digits (%08X).
func getVolumeInfo(root string) (label, serial string, err error) {
	rootPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return "", "", err
	}
	var nameBuf [261]uint16 // MAX_PATH + 1
	var serialNum, maxComponentLen, fsFlags uint32
	r, _, callErr := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)),
		uintptr(unsafe.Pointer(&serialNum)),
		uintptr(unsafe.Pointer(&maxComponentLen)),
		uintptr(unsafe.Pointer(&fsFlags)),
		0, 0, // file-system name buffer: not needed
	)
	if r == 0 {
		return "", "", callErr
	}
	return syscall.UTF16ToString(nameBuf[:]), fmt.Sprintf("%08X", serialNum), nil
}

// getDriveSize returns the total size of the drive in bytes (the second output
// of GetDiskFreeSpaceExW).
func getDriveSize(root string) (int64, error) {
	rootPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return 0, err
	}
	var freeAvailable, totalBytes, totalFree uint64
	r, _, callErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&freeAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, callErr
	}
	return int64(totalBytes), nil
}
