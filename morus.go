// morus.go - High-level interface
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package morus implements the MORUS-1280-256 Authenticated Cipher.
//
// This implementation is derived from the reference implementation by
// Hongjun Wu and Tao Huang.
package morus

import (
	"crypto/subtle"
	"errors"
)

const (
	// KeySize is the size of a key in bytes.
	KeySize = 32

	// NonceSize is the size of a nonce in bytes.
	NonceSize = 16

	// TagSize is the size of an authentication tag in bytes.
	TagSize = 16

	// Version is the version of the MORUS specification implemented.
	Version = "2.0"
)

var (
	// ErrInvalidKeySize is the error thrown via a panic when a key is an
	// invalid size.
	ErrInvalidKeySize = errors.New("morus: invalid key size")

	// ErrInvalidNonceSize is the error thrown via a panic when a nonce is
	// an invalid size.
	ErrInvalidNonceSize = errors.New("morus: invalid nonce size")

	// ErrOpen is the error returned when the message authentication fails
	// during an Open call.
	ErrOpen = errors.New("morus: message authentication failed")
)

// AEAD is a MORUS instance, implementing crypto/cipher.AEAD.
type AEAD struct {
	key []byte
}

// NonceSize returns the size of the nonce that must be passed to Seal and
// Open.
func (ae *AEAD) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a plaintext
// and its ciphertext.
func (ae *AEAD) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// The plaintext and dst must overlap exactly or not at all. To reuse
// plaintext's storage for the encrypted output, use plaintext[:0] as dst.
func (ae *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}
	dst = aeadEncrypt(dst, plaintext, additionalData, nonce, ae.key)
	return dst
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// The ciphertext and dst must overlap exactly or not at all. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (ae *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var err error
	var ok bool

	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}
	dst, ok = aeadDecrypt(dst, ciphertext, additionalData, nonce, ae.key)
	if !ok {
		err = ErrOpen
	}
	return dst, err
}

// Reset securely purges stored sensitive data from the AEAD instance.
func (ae *AEAD) Reset() {
	burnBytes(ae.key)
}

// New returns a new keyed MORUS-1280-256 instance.
func New(key []byte) *AEAD {
	if len(key) != KeySize {
		panic(ErrInvalidKeySize)
	}
	return &AEAD{key: append([]byte{}, key...)}
}

func aeadEncrypt(c, m, a, nonce, key []byte) []byte {
	var s state
	mLen := len(m)

	ret, out := sliceForAppend(c, mLen+TagSize)

	hardwareAccelImpl.initFn(&s, key, nonce)
	hardwareAccelImpl.absorbDataFn(&s, a)
	hardwareAccelImpl.encryptDataFn(&s, out, m)
	hardwareAccelImpl.finalizeFn(&s, uint64(mLen), uint64(len(a)), out[mLen:])

	burnUint64s(s.s[:])

	return ret
}

func aeadDecrypt(m, c, a, nonce, key []byte) ([]byte, bool) {
	var s state
	var tag [TagSize]byte
	cLen := len(c)

	if cLen < TagSize {
		return nil, false
	}

	mLen := cLen - TagSize
	ret, out := sliceForAppend(m, mLen)

	hardwareAccelImpl.initFn(&s, key, nonce)
	hardwareAccelImpl.absorbDataFn(&s, a)
	hardwareAccelImpl.decryptDataFn(&s, out, c[:mLen])
	hardwareAccelImpl.finalizeFn(&s, uint64(mLen), uint64(len(a)), tag[:])

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

// Shamelessly stolen from the Go runtime library.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
