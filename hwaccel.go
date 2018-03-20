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
		initFn:        initRef,
		absorbDataFn:  absorbDataRef,
		encryptDataFn: encryptDataRef,
		decryptDataFn: decryptDataRef,
		finalizeFn:    finalizeRef,
	}
)

type hwaccelImpl struct {
	name          string
	initFn        func(*state, []byte, []byte)
	absorbDataFn  func(*state, []byte)
	encryptDataFn func(*state, []byte, []byte)
	decryptDataFn func(*state, []byte, []byte)
	finalizeFn    func(*state, uint64, uint64, []byte)
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
