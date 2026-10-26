//go:build !windows

// Non-Windows stub so the package still builds and can be reviewed on Linux.
// The original is a Windows program; removable-drive enumeration only has a
// real implementation there (usb_windows.go).
package lock

import "errors"

// GetUSBCandidates is unimplemented off Windows.
func GetUSBCandidates() ([]USBInfo, error) {
	return nil, errors.New("removable-drive enumeration is only implemented on Windows")
}
