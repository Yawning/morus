// burn_unsafe.go - burn (unsafe available)
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build !noasm,!appengine

package morus

import "unsafe"

//go:noescape
//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

// Note: The compiler in theory always optimizes the "safe" variant of this
// which uses a naive for loop to the unsafe equivalent, but there's no reason
// to trust it.

func burnBytes(b []byte) {
	memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)))
}

func burnUint64s(b []uint64) {
	l := len(b) * 8
	memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(l))
}
