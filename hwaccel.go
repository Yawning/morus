// hwaccel.go - Hardware acceleration hooks
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package morus

var (
	isHardwareAccelerated = false
	hardwareAccelImpl     = implReference

	implReference = &hwaccelImpl{
		name:          "Reference",
		aeadEncryptFn: aeadEncryptRef,
		aeadDecryptFn: aeadDecryptRef,
	}
)

type hwaccelImpl struct {
	name          string
	aeadEncryptFn func([]byte, []byte, []byte, []byte, []byte) []byte
	aeadDecryptFn func([]byte, []byte, []byte, []byte, []byte) ([]byte, bool)
}

func forceDisableHardwareAcceleration() {
	isHardwareAccelerated = false
	hardwareAccelImpl = implReference
}

// IsHardwareAccelerated returns true iff the MORUS implementation will use
// hardware acceleration (eg: AVX2).
func IsHardwareAccelerated() bool {
	return isHardwareAccelerated
}

func init() {
	initHardwareAcceleration()
}
