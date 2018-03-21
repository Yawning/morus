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
func initAVX2(s *uint64, key, iv *byte)

//go:noescape
func absorbBlocksAVX2(s *uint64, in *byte, blocks uint64)

//go:noescape
func encryptBlocksAVX2(s *uint64, out, in *byte, blocks uint64)

//go:noescape
func decryptBlocksAVX2(s *uint64, out, in *byte, blocks uint64)

//go:noescape
func decryptLastBlockAVX2(s *uint64, out, in *byte, inLen uint64)

//go:noescape
func finalizeAVX2(s *uint64, tag *byte, lastBlock *uint64)

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

type ymmState struct {
	s [20]uint64
}

func (s *ymmState) init(key, iv []byte) {
	initAVX2(&s.s[0], &key[0], &iv[0])
}

func (s *ymmState) absorbData(in []byte) {
	inLen, off := len(in), 0
	if inLen == 0 {
		return
	}

	if inBlocks := inLen / blockSize; inBlocks > 0 {
		absorbBlocksAVX2(&s.s[0], &in[0], uint64(inBlocks))
		off += inBlocks * blockSize
	}
	in = in[off:]

	if len(in) > 0 {
		var tmp [blockSize]byte
		copy(tmp[:], in)
		absorbBlocksAVX2(&s.s[0], &tmp[0], 1)
	}
}

func (s *ymmState) encryptData(out, in []byte) {
	inLen, off := len(in), 0
	if inLen == 0 {
		return
	}

	if inBlocks := inLen / blockSize; inBlocks > 0 {
		encryptBlocksAVX2(&s.s[0], &out[0], &in[0], uint64(inBlocks))
		off += inBlocks * blockSize
	}
	out, in = out[off:], in[off:]

	if len(in) > 0 {
		var tmp [blockSize]byte
		copy(tmp[:], in)
		encryptBlocksAVX2(&s.s[0], &tmp[0], &tmp[0], 1)
		copy(out, tmp[:])
	}
}

func (s *ymmState) decryptData(out, in []byte) {
	inLen, off := len(in), 0
	if inLen == 0 {
		return
	}

	if inBlocks := inLen / blockSize; inBlocks > 0 {
		decryptBlocksAVX2(&s.s[0], &out[0], &in[0], uint64(inBlocks))
		off += inBlocks * blockSize
	}
	out, in = out[off:], in[off:]

	if len(in) > 0 {
		var tmp [blockSize]byte
		copy(tmp[:], in)
		decryptLastBlockAVX2(&s.s[0], &tmp[0], &tmp[0], uint64(len(in)))
		copy(out, tmp[:])
	}
}

func (s *ymmState) finalize(msgLen, adLen uint64, tag []byte) {
	var lastBlock = [4]uint64{adLen << 3, msgLen << 3, 0, 0}
	finalizeAVX2(&s.s[0], &tag[0], &lastBlock[0])
}

func aeadEncryptYMM(c, m, a, nonce, key []byte) []byte {
	var s ymmState
	mLen := len(m)

	ret, out := sliceForAppend(c, mLen+TagSize)

	s.init(key, nonce)
	s.absorbData(a)
	s.encryptData(out, m)
	s.finalize(uint64(mLen), uint64(len(a)), out[mLen:])

	burnUint64s(s.s[:])

	return ret
}

func aeadDecryptYMM(m, c, a, nonce, key []byte) ([]byte, bool) {
	var s ymmState
	var tag [TagSize]byte
	cLen := len(c)

	if cLen < TagSize {
		return nil, false
	}

	mLen := cLen - TagSize
	ret, out := sliceForAppend(m, mLen)

	s.init(key, nonce)
	s.absorbData(a)
	s.decryptData(out, c[:mLen])
	s.finalize(uint64(mLen), uint64(len(a)), tag[:])

	srcTag := c[mLen:]
	ok := subtle.ConstantTimeCompare(srcTag, tag[:]) == 1
	if !ok && mLen > 0 {
		// Burn decrypted plaintext on auth failure.
		burnBytes(out[:mLen])
		ret = nil
	}

	burnUint64s(s.s[:])

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
