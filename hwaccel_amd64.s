// +build !noasm,go1.10
// hwaccel_amd64.s - AMD64 optimized routines
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

#include "textflag.h"

// func cpuidAmd64(cpuidParams *uint32)
TEXT ·cpuidAmd64(SB), NOSPLIT, $0-8
	MOVQ cpuidParams+0(FP), R15
	MOVL 0(R15), AX
	MOVL 8(R15), CX
	CPUID
	MOVL AX, 0(R15)
	MOVL BX, 4(R15)
	MOVL CX, 8(R15)
	MOVL DX, 12(R15)
	RET

// func xgetbv0Amd64(xcrVec *uint32)
TEXT ·xgetbv0Amd64(SB), NOSPLIT, $0-8
	MOVQ xcrVec+0(FP), BX
	XORL CX, CX
	XGETBV
	MOVL AX, 0(BX)
	MOVL DX, 4(BX)
	RET

// Some useful macros for loading/storing the state, and the state update
// function, along with aliases for the registers used for readability.

// YMM Registers: Sx -> State, Mx -> Message, Tx -> Temporary
//
// Note: Routines use other registers as temporaries, the Tx aliases are
// for those that are clobbered by STATE_UPDATE().
#define S0 Y0
#define S1 Y1
#define S2 Y2
#define S3 Y3
#define S4 Y4
#define M0 Y5
#define T0 Y14
#define T1 Y15

#define LOAD_STATE(SRC) \
	VMOVDQU (SRC), S0    \
	VMOVDQU 32(SRC), S1  \
	VMOVDQU 64(SRC), S2  \
	VMOVDQU 96(SRC), S3  \
	VMOVDQU 128(SRC), S4

#define STORE_STATE(DST) \
	VMOVDQU S0, (DST)    \
	VMOVDQU S1, 32(DST)  \
	VMOVDQU S2, 64(DST)  \
	VMOVDQU S3, 96(DST)  \
	VMOVDQU S4, 128(DST)

// This essentially naively translated from the intrinsics, but neither GCC nor
// clang's idea of what this should be appears to be better on Broadwell, and
// there is a benefit to being easy to cross reference with the upstream
// implementation.
#define STATE_UPDATE() \
	VPXOR  S0, S3, S0    \
	VPAND  S1, S2, T0    \
	VPXOR  S0, T0, S0    \
	VPSLLQ $13, S0, T0   \
	VPSRLQ $51, S0, T1   \
	VPOR   T0, T1, S0    \
	VPERMQ $-109, S3, S3 \
	                     \
	VPXOR  S1, M0, S1    \
	VPXOR  S1, S4, S1    \
	VPAND  S2, S3, T0    \
	VPXOR  S1, T0, S1    \
	VPSLLQ $46, S1, T0   \
	VPSRLQ $18, S1, T1   \
	VPOR   T0, T1, S1    \
	VPERMQ $78, S4, S4   \
	                     \
	VPXOR  S2, M0, S2    \
	VPXOR  S2, S0, S2    \
	VPAND  S3, S4, T0    \
	VPXOR  S2, T0, S2    \
	VPSLLQ $38, S2, T0   \
	VPSRLQ $26, S2, T1   \
	VPOR   T0, T1, S2    \
	VPERMQ $57, S0, S0   \
	                     \
	VPXOR  S3, M0, S3    \
	VPXOR  S3, S1, S3    \
	VPAND  S4, S0, T0    \
	VPXOR  S3, T0, S3    \
	VPSLLQ $7, S3, T0    \
	VPSRLQ $57, S3, T1   \
	VPOR   T0, T1, S3    \
	VPERMQ $78, S1, S1   \
	                     \
	VPXOR  S4, M0, S4    \
	VPXOR  S4, S2, S4    \
	VPAND  S0, S1, T0    \
	VPXOR  S4, T0, S4    \
	VPSLLQ $4, S4, T0    \
	VPSRLQ $60, S4, T1   \
	VPOR   T0, T1, S4    \
	VPERMQ $-109, S2, S2

// func initAVX2(s *uint64, key, iv *byte)
TEXT ·initAVX2(SB), NOSPLIT, $0-24
	MOVQ s+0(FP), R8
	MOVQ key+8(FP), R9
	MOVQ iv+16(FP), R10

	VPXOR    S0, S0, S0
	MOVOU    (R10), X0
	VMOVDQU  (R9), S1
	VPCMPEQD S2, S2, S2
	VPXOR    S3, S3, S3
	VMOVDQU  ·initializationConstants(SB), S4
	VPXOR    M0, M0, M0
	VMOVDQA  S1, Y6

	MOVQ $16, AX

initloop:
	STATE_UPDATE()
	SUBQ $1, AX
	JNZ  initloop

	VPXOR Y6, S1, S1
	STORE_STATE(R8)

	VZEROUPPER
	RET

// func absorbBlocksAVX2(s *uint64, in *byte, blocks uint64)
TEXT ·absorbBlocksAVX2(SB), NOSPLIT, $0-24
	MOVQ s+0(FP), R8
	MOVQ in+8(FP), R10
	MOVQ blocks+16(FP), R11

	LOAD_STATE(R8)

loopblocks:
	VMOVDQU (R10), M0
	STATE_UPDATE()
	ADDQ    $32, R10
	SUBQ    $1, R11
	JNZ     loopblocks

	STORE_STATE(R8)

	VZEROUPPER
	RET

// func encryptBlocksAVX2(s *uint64, out, in *byte, blocks uint64)
TEXT ·encryptBlocksAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ out+8(FP), R9
	MOVQ in+16(FP), R10
	MOVQ blocks+24(FP), R11

	LOAD_STATE(R8)

loopblocks:
	VMOVDQU (R10), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, Y6
	VMOVDQU Y6, (R9)
	STATE_UPDATE()
	ADDQ    $32, R9
	ADDQ    $32, R10
	SUBQ    $1, R11
	JNZ     loopblocks

	STORE_STATE(R8)

	VZEROUPPER
	RET

// func decryptBlocksAVX2(s *uint64, out, in *byte, blocks uint64)
TEXT ·decryptBlocksAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ out+8(FP), R9
	MOVQ in+16(FP), R10
	MOVQ blocks+24(FP), R11

	LOAD_STATE(R8)

loopblocks:
	VMOVDQU (R10), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, M0
	VMOVDQU M0, (R9)
	STATE_UPDATE()
	ADDQ    $32, R9
	ADDQ    $32, R10
	SUBQ    $1, R11
	JNZ     loopblocks

	STORE_STATE(R8)

	VZEROUPPER
	RET

// func decryptLastBlockAVX2(s *uint64, out, in *byte, inLen uint64)
TEXT ·decryptLastBlockAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ out+8(FP), R9
	MOVQ in+16(FP), R10
	MOVQ inLen+24(FP), R11

	LOAD_STATE(R8)

	VMOVDQU (R10), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, M0
	VMOVDQU M0, (R9)

	MOVQ R11, AX

loopclear:
	MOVB $0, (R9)(AX*1)
	ADDQ $1, AX
	CMPQ AX, $32
	JNE  loopclear

	VMOVDQU (R9), M0
	STATE_UPDATE()
	STORE_STATE(R8)

	VZEROUPPER
	RET

// func finalizeAVX2(s *uint64, tag *byte, lastBlock *uint64)
TEXT ·finalizeAVX2(SB), NOSPLIT, $0-24
	MOVQ s+0(FP), R8
	MOVQ tag+8(FP), R9
	MOVQ lastBlock+16(FP), R10

	LOAD_STATE(R8)

	VPXOR   S4, S0, S4
	VMOVDQU (R10), M0

	MOVQ $10, AX

finalloop:
	STATE_UPDATE()
	SUBQ $1, AX
	JNZ  finalloop

	VPERMQ $57, S1, Y6
	VPXOR  S0, Y6, Y6
	VPAND  S2, S3, Y7
	VPXOR  Y6, Y7, Y7
	MOVOU  X7, (R9)

	VZEROUPPER
	RET
