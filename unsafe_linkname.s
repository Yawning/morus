// unsafe_linkname.s - go:linkname workaround
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build !noasm,!appengine

// The `go:linkname` pragma does not work without an empty assembly file.
// See: https://github.com/golang/go/issues/15006.
