// burn_test.go - burn tests
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package morus

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// While it seems somewhat silly to test memset, the unsafe implementation
// uses trickery to reach into the runtime library, so it's worth exercising.

func TestBurnBytes(t *testing.T) {
	require := require.New(t)

	var buf [1024]byte
	require.Zero(buf, "buf: Before random read")
	_, err := rand.Read(buf[:])
	require.NoError(err, "rand.Read()")
	require.NotZero(buf, "buf: After random read")

	burnBytes(buf[:])
	require.Zero(buf, "buf: After burnBytes()")
}

func TestBurnUint64s(t *testing.T) {
	require := require.New(t)

	var buf [1024]uint64
	require.Zero(buf, "buf: Before random read")

	err := binary.Read(rand.Reader, binary.LittleEndian, &buf)
	require.NoError(err, "binary.Read(rand.Reader)")
	require.NotZero(buf, "buf: After random read")

	burnUint64s(buf[:])
	require.Zero(buf, "buf: After burnUint64s()")
}
