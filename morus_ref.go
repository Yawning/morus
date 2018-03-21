// morus_ref.go - Reference (portable) implementation
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package morus

import (
	"crypto/subtle"
	"math/bits"
)

const (
	n1 = 13
	n2 = 46
	n3 = 38
	n4 = 7
	n5 = 4

	blockSize = 32
)

type state struct {
	s [20]uint64
}

func (s *state) update(msgBlk []byte) {
	var tmp uint64

	s00, s01, s02, s03, s10, s11, s12, s13, s20, s21, s22, s23, s30, s31, s32, s33, s40, s41, s42, s43 := s.s[0], s.s[1], s.s[2], s.s[3], s.s[4], s.s[5], s.s[6], s.s[7], s.s[8], s.s[9], s.s[10], s.s[11], s.s[12], s.s[13], s.s[14], s.s[15], s.s[16], s.s[17], s.s[18], s.s[19]

	_ = msgBlk[31] // Bounds check elimination
	m0 := byteOrder.Uint64(msgBlk[0:8])
	m1 := byteOrder.Uint64(msgBlk[8:16])
	m2 := byteOrder.Uint64(msgBlk[16:24])
	m3 := byteOrder.Uint64(msgBlk[24:32])

	s00 ^= s30
	s01 ^= s31
	s02 ^= s32
	s03 ^= s33
	s00 ^= s10 & s20
	s01 ^= s11 & s21
	s02 ^= s12 & s22
	s03 ^= s13 & s23
	s00 = bits.RotateLeft64(s00, n1)
	s01 = bits.RotateLeft64(s01, n1)
	s02 = bits.RotateLeft64(s02, n1)
	s03 = bits.RotateLeft64(s03, n1)
	tmp = s33
	s33 = s32
	s32 = s31
	s31 = s30
	s30 = tmp

	s10 ^= m0
	s11 ^= m1
	s12 ^= m2
	s13 ^= m3
	s10 ^= s40
	s11 ^= s41
	s12 ^= s42
	s13 ^= s43
	s10 ^= s20 & s30
	s11 ^= s21 & s31
	s12 ^= s22 & s32
	s13 ^= s23 & s33
	s10 = bits.RotateLeft64(s10, n2)
	s11 = bits.RotateLeft64(s11, n2)
	s12 = bits.RotateLeft64(s12, n2)
	s13 = bits.RotateLeft64(s13, n2)
	s43, s41 = s41, s43
	s42, s40 = s40, s42

	s20 ^= m0
	s21 ^= m1
	s22 ^= m2
	s23 ^= m3
	s20 ^= s00
	s21 ^= s01
	s22 ^= s02
	s23 ^= s03
	s20 ^= s30 & s40
	s21 ^= s31 & s41
	s22 ^= s32 & s42
	s23 ^= s33 & s43
	s20 = bits.RotateLeft64(s20, n3)
	s21 = bits.RotateLeft64(s21, n3)
	s22 = bits.RotateLeft64(s22, n3)
	s23 = bits.RotateLeft64(s23, n3)
	tmp = s00
	s00 = s01
	s01 = s02
	s02 = s03
	s03 = tmp

	s30 ^= m0
	s31 ^= m1
	s32 ^= m2
	s33 ^= m3
	s30 ^= s10
	s31 ^= s11
	s32 ^= s12
	s33 ^= s13
	s30 ^= s40 & s00
	s31 ^= s41 & s01
	s32 ^= s42 & s02
	s33 ^= s43 & s03
	s30 = bits.RotateLeft64(s30, n4)
	s31 = bits.RotateLeft64(s31, n4)
	s32 = bits.RotateLeft64(s32, n4)
	s33 = bits.RotateLeft64(s33, n4)
	s13, s11 = s11, s13
	s12, s10 = s10, s12

	s40 ^= m0
	s41 ^= m1
	s42 ^= m2
	s43 ^= m3
	s40 ^= s20
	s41 ^= s21
	s42 ^= s22
	s43 ^= s23
	s40 ^= s00 & s10
	s41 ^= s01 & s11
	s42 ^= s02 & s12
	s43 ^= s03 & s13
	s40 = bits.RotateLeft64(s40, n5)
	s41 = bits.RotateLeft64(s41, n5)
	s42 = bits.RotateLeft64(s42, n5)
	s43 = bits.RotateLeft64(s43, n5)
	tmp = s23
	s23 = s22
	s22 = s21
	s21 = s20
	s20 = tmp

	s.s[0], s.s[1], s.s[2], s.s[3], s.s[4], s.s[5], s.s[6], s.s[7], s.s[8], s.s[9], s.s[10], s.s[11], s.s[12], s.s[13], s.s[14], s.s[15], s.s[16], s.s[17], s.s[18], s.s[19] = s00, s01, s02, s03, s10, s11, s12, s13, s20, s21, s22, s23, s30, s31, s32, s33, s40, s41, s42, s43
}

func (s *state) encryptBlock(out, in []byte) {
	_, _ = in[31], out[31] // Bounds check elimination
	in0 := byteOrder.Uint64(in[0:8])
	in1 := byteOrder.Uint64(in[8:16])
	in2 := byteOrder.Uint64(in[16:24])
	in3 := byteOrder.Uint64(in[24:32])

	out0 := in0 ^ s.s[0] ^ s.s[5] ^ (s.s[8] & s.s[12])
	out1 := in1 ^ s.s[1] ^ s.s[6] ^ (s.s[9] & s.s[13])
	out2 := in2 ^ s.s[2] ^ s.s[7] ^ (s.s[10] & s.s[14])
	out3 := in3 ^ s.s[3] ^ s.s[4] ^ (s.s[11] & s.s[15])

	s.update(in[:32])

	// Doing this last lets this work in place.
	byteOrder.PutUint64(out[0:8], out0)
	byteOrder.PutUint64(out[8:16], out1)
	byteOrder.PutUint64(out[16:24], out2)
	byteOrder.PutUint64(out[24:32], out3)
}

func (s *state) decryptBlockCommon(out, in []byte) {
	_, _ = in[31], out[31] // Bounds check elimination
	in0 := byteOrder.Uint64(in[0:8])
	in1 := byteOrder.Uint64(in[8:16])
	in2 := byteOrder.Uint64(in[16:24])
	in3 := byteOrder.Uint64(in[24:32])

	out0 := in0 ^ s.s[0] ^ s.s[5] ^ (s.s[8] & s.s[12])
	out1 := in1 ^ s.s[1] ^ s.s[6] ^ (s.s[9] & s.s[13])
	out2 := in2 ^ s.s[2] ^ s.s[7] ^ (s.s[10] & s.s[14])
	out3 := in3 ^ s.s[3] ^ s.s[4] ^ (s.s[11] & s.s[15])

	byteOrder.PutUint64(out[0:8], out0)
	byteOrder.PutUint64(out[8:16], out1)
	byteOrder.PutUint64(out[16:24], out2)
	byteOrder.PutUint64(out[24:32], out3)
}

func (s *state) decryptBlock(out, in []byte) {
	s.decryptBlockCommon(out, in)
	s.update(out[:32])
}

func (s *state) decryptPartialBlock(out, in []byte) {
	var tmp [blockSize]byte
	copy(tmp[:], in)
	s.decryptBlockCommon(tmp[:], tmp[:])
	copy(out, tmp[:])

	burnBytes(tmp[len(in):])
	s.update(tmp[:])
}

func (s *state) init(key, iv []byte) {
	_, _ = key[31], iv[15] // Bounds check elimination
	k0 := byteOrder.Uint64(key[0:8])
	k1 := byteOrder.Uint64(key[8:16])
	k2 := byteOrder.Uint64(key[16:24])
	k3 := byteOrder.Uint64(key[24:32])

	s.s[0] = byteOrder.Uint64(iv[0:8])
	s.s[1] = byteOrder.Uint64(iv[8:16])
	s.s[2], s.s[3] = 0, 0
	s.s[4], s.s[5], s.s[6], s.s[7] = k0, k1, k2, k3
	s.s[8], s.s[9], s.s[10], s.s[11] = 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
	s.s[12], s.s[13], s.s[14], s.s[15] = 0, 0, 0, 0
	s.s[16] = initializationConstants[0]
	s.s[17] = initializationConstants[1]
	s.s[18] = initializationConstants[2]
	s.s[19] = initializationConstants[3]

	var tmp [blockSize]byte
	for i := 0; i < 16; i++ {
		s.update(tmp[:])
	}
	s.s[4] ^= k0
	s.s[5] ^= k1
	s.s[6] ^= k2
	s.s[7] ^= k3

	burnBytes(tmp[:])
}

func (s *state) absorbData(in []byte) {
	inLen, off := len(in), 0
	if inLen == 0 {
		return
	}

	for inLen >= blockSize {
		s.update(in[off : off+blockSize])
		inLen, off = inLen-blockSize, off+blockSize
	}

	if inLen > 0 {
		var tmp [blockSize]byte
		copy(tmp[:], in[off:])
		s.update(tmp[:])
	}
}

func (s *state) encryptData(out, in []byte) {
	inLen, off := len(in), 0
	if inLen == 0 {
		return
	}

	for inLen >= blockSize {
		s.encryptBlock(out[off:off+blockSize], in[off:off+blockSize])
		inLen, off = inLen-blockSize, off+blockSize
	}

	if inLen > 0 {
		var tmp [blockSize]byte
		copy(tmp[:], in[off:])
		s.encryptBlock(tmp[:], tmp[:])
		copy(out[off:], tmp[:])
	}
}

func (s *state) decryptData(out, in []byte) {
	inLen, off := len(in), 0
	if inLen == 0 {
		return
	}

	for inLen >= blockSize {
		s.decryptBlock(out[off:off+blockSize], in[off:off+blockSize])
		inLen, off = inLen-blockSize, off+blockSize
	}

	if inLen > 0 {
		s.decryptPartialBlock(out[off:], in[off:])
	}
}

func (s *state) finalize(msgLen, adLen uint64, tag []byte) {
	var tmp [blockSize]byte
	byteOrder.PutUint64(tmp[0:8], (adLen << 3))
	byteOrder.PutUint64(tmp[8:16], (msgLen << 3))

	s.s[16] ^= s.s[0]
	s.s[17] ^= s.s[1]
	s.s[18] ^= s.s[2]
	s.s[19] ^= s.s[3]

	for i := 0; i < 10; i++ {
		s.update(tmp[:])
	}

	s.s[0] = s.s[0] ^ s.s[5] ^ (s.s[8] & s.s[12])
	s.s[1] = s.s[1] ^ s.s[6] ^ (s.s[9] & s.s[13])

	_ = tag[15] // Bounds check elimination
	byteOrder.PutUint64(tag[0:8], s.s[0])
	byteOrder.PutUint64(tag[8:16], s.s[1])

	burnBytes(tmp[:])
}

func aeadEncryptRef(c, m, a, nonce, key []byte) []byte {
	var s state
	mLen := len(m)

	ret, out := sliceForAppend(c, mLen+TagSize)

	s.init(key, nonce)
	s.absorbData(a)
	s.encryptData(out, m)
	s.finalize(uint64(mLen), uint64(len(a)), out[mLen:])

	burnUint64s(s.s[:])

	return ret
}

func aeadDecryptRef(m, c, a, nonce, key []byte) ([]byte, bool) {
	var s state
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
