// hwaccel_amd64.go - AMD64 optimized routines
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!noasm,go1.10

package morus

import "crypto/subtle"

//go:noescape
func cpuidAmd64(cpuidParams *uint32)

//go:noescape
func xgetbv0Amd64(xcrVec *uint32)

//go:noescape
func aeadEncryptAVX2(c, m, a []byte, nonce, key *byte)

//go:noescape
func aeadDecryptAVX2(m, c, a []byte, nonce, key, tag *byte)

func supportsAVX2() bool {
	// https://software.intel.com/en-us/articles/how-to-detect-new-instruction-support-in-the-4th-generation-intel-core-processor-family
	const (
		osXsaveBit = 1 << 27
		avx2Bit    = 1 << 5
	)

	// Check to see if CPUID actually supports the leaf that indicates AVX2.
	// CPUID.(EAX=0H, ECX=0H) >= 7
	regs := [4]uint32{0x00}
	cpuidAmd64(&regs[0])
	if regs[0] < 7 {
		return false
	}

	// Check to see if the OS knows how to save/restore XMM/YMM state.
	// CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1
	regs = [4]uint32{0x01}
	cpuidAmd64(&regs[0])
	if regs[2]&osXsaveBit == 0 {
		return false
	}
	xcrRegs := [2]uint32{}
	xgetbv0Amd64(&xcrRegs[0])
	if xcrRegs[0]&6 != 6 {
		return false
	}

	// Check for AVX2 support.
	// CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1
	regs = [4]uint32{0x07}
	cpuidAmd64(&regs[0])
	return regs[1]&avx2Bit != 0
}

func aeadEncryptYMM(c, m, a, nonce, key []byte) []byte {
	mLen := len(m)
	ret, out := sliceForAppend(c, mLen+TagSize)
	aeadEncryptAVX2(out, m, a, &nonce[0], &key[0])

	return ret
}

func aeadDecryptYMM(m, c, a, nonce, key []byte) ([]byte, bool) {
	var tag [TagSize]byte
	cLen := len(c)

	if cLen < TagSize {
		return nil, false
	}

	mLen := cLen - TagSize
	ret, out := sliceForAppend(m, mLen)
	aeadDecryptAVX2(out, c[:mLen], a, &nonce[0], &key[0], &tag[0])

	srcTag := c[mLen:]
	ok := subtle.ConstantTimeCompare(srcTag, tag[:]) == 1
	if !ok && mLen > 0 {
		// Burn decrypted plaintext on auth failure.
		burnBytes(out[:mLen])
		ret = nil
	}

	return ret, ok
}

var implAVX2 = &hwaccelImpl{
	name:          "AVX2",
	aeadEncryptFn: aeadEncryptYMM,
	aeadDecryptFn: aeadDecryptYMM,
}

func initHardwareAcceleration() {
	if supportsAVX2() {
		isHardwareAccelerated = true
		hardwareAccelImpl = implAVX2
	}
}
