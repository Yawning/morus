// burn_safe.go - burn (unsafe not available)
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build noasm appengine

package morus

import "unsafe"

func burnBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func burnUint64s(b []uint64) {
	for i := range b {
		b[i] = 0
	}
}
