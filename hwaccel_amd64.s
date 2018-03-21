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
// GP Registers: RAX, RBX, RCX -> Temporary
#define S0 Y0
#define S1 Y1
#define S2 Y2
#define S3 Y3
#define S4 Y4
#define M0 Y5
#define T0 Y14
#define T1 Y15

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

#define COPY(DST, SRC, LEN) \
	MOVQ SRC, SI \
	MOVQ DST, DI \
	MOVQ LEN, CX \
	REP          \
	MOVSB

#define INIT_STATE(IV, KEY) \
	VPXOR     S0, S0, S0                       \
	MOVOU     (IV), X0                         \
	VMOVDQU   (KEY), S1                        \
	VPCMPEQD  S2, S2, S2                       \
	VPXOR     S3, S3, S3                       \
	VMOVDQU   ·initializationConstants(SB), S4 \
	VPXOR     M0, M0, M0                       \
	VMOVDQA   S1, Y6                           \
	MOVQ      $16, AX                          \
	                                           \
initLoop:                                    \
	STATE_UPDATE()                             \
	SUBQ      $1, AX                           \
	JNZ       initLoop                         \
	                                           \
	VPXOR     Y6, S1, S1

#define ABSORB_BLOCKS(A, ALEN, SCRATCH) \
	MOVQ            ALEN, AX       \
	SHRQ            $5, AX         \
	JZ              absorbPartial  \
loopAbsorbFull:                  \
	VMOVDQU         (A), M0        \
	STATE_UPDATE()                 \
	ADDQ            $32, A         \
	SUBQ            $1, AX         \
	JNZ             loopAbsorbFull \
absorbPartial:                   \
	ANDQ            $31, ALEN      \
	JZ              absorbDone     \
	COPY(SCRATCH, A, ALEN)         \
	VMOVDQU         (SCRATCH), M0  \
	STATE_UPDATE()                 \
absorbDone:

#define FINALIZE(TAG, ALEN, MLEN, SCRATCH) \
	SHLQ       $3, ALEN         \
	MOVQ       ALEN, (SCRATCH)  \
	SHLQ       $3, MLEN         \
	MOVQ       MLEN, 8(SCRATCH) \
	                            \
	VPXOR      S4, S0, S4       \
	VMOVDQU    (SCRATCH), M0    \
	                            \
	MOVQ       $10, AX          \
loopFinal:                    \
	STATE_UPDATE()              \
	SUBQ       $1, AX           \
	JNZ        loopFinal        \
	                            \
	VPERMQ     $57, S1, Y6      \
	VPXOR      S0, Y6, Y6       \
	VPAND      S2, S3, Y7       \
	VPXOR      Y6, Y7, Y7       \
	MOVOU      X7, (TAG)

// func aeadEncryptAVX2(c, m, a []byte, nonce, key *byte)
TEXT ·aeadEncryptAVX2(SB), NOSPLIT, $32-88
	MOVQ    SP, R15
	VPXOR   Y13, Y13, Y13
	VMOVDQU Y13, (R15)
	CLD

	// Initialize the state.
	MOVQ nonce+72(FP), R8
	MOVQ key+80(FP), R9
	INIT_STATE(R8, R9)

	// Absorb the AD.
	MOVQ a+48(FP), R8 // &a[0] -> R8
	MOVQ a+56(FP), R9 // len(a) -> R9
	ABSORB_BLOCKS(R8, R9, R15)

	// Encrypt the data.
	MOVQ m+24(FP), R8 // &m[0] -> R8
	MOVQ m+32(FP), R9 // len(m) -> R9
	MOVQ c+0(FP), R10 // &c[0] -> R10

	MOVQ R9, AX
	SHRQ $5, AX
	JZ   encryptPartial

loopEncryptFull:
	VMOVDQU (R8), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, Y6
	VMOVDQU Y6, (R10)
	STATE_UPDATE()
	ADDQ    $32, R8
	ADDQ    $32, R10
	SUBQ    $1, AX
	JNZ     loopEncryptFull

encryptPartial:
	ANDQ    $31, R9
	JZ      encryptDone
	VMOVDQU Y13, (R15)
	COPY(R15, R8, R9)
	VMOVDQU (R15), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, Y6
	VMOVDQU Y6, (R15)
	STATE_UPDATE()
	COPY(R10, R15, R9)
	ADDQ    R9, R10

encryptDone:

	// Finalize and write the tag.
	MOVQ    a+56(FP), R8 // len(a) -> R8
	MOVQ    m+32(FP), R9 // len(m) -> R9
	VMOVDQU Y13, (R15)
	FINALIZE(R10, R8, R9, R15)

	VMOVDQU Y13, (R15)
	VZEROUPPER
	RET

// func aeadDecryptAVX2(m, c, a []byte, nonce, key, tag *byte)
TEXT ·aeadDecryptAVX2(SB), NOSPLIT, $32-96
	MOVQ    SP, R15
	VPXOR   Y13, Y13, Y13
	VMOVDQU Y13, (R15)
	CLD

	// Initialize the state.
	MOVQ nonce+72(FP), R8
	MOVQ key+80(FP), R9
	INIT_STATE(R8, R9)

	// Absorb the AD.
	MOVQ a+48(FP), R8 // &a[0] -> R8
	MOVQ a+56(FP), R9 // len(a) -> R9
	ABSORB_BLOCKS(R8, R9, R15)

	// Decrypt the data.
	MOVQ c+24(FP), R8 // &c[0] -> R8
	MOVQ c+32(FP), R9 // len(c) -> R9
	MOVQ m+0(FP), R10 // &m[0] -> R10

	MOVQ R9, AX
	SHRQ $5, AX
	JZ   decryptPartial

loopDecryptFull:
	VMOVDQU (R8), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, M0
	VMOVDQU M0, (R10)
	STATE_UPDATE()
	ADDQ    $32, R8
	ADDQ    $32, R10
	SUBQ    $1, AX
	JNZ     loopDecryptFull

decryptPartial:
	ANDQ    $31, R9
	JZ      decryptDone
	VMOVDQU Y13, (R15)
	COPY(R15, R8, R9)
	VMOVDQU (R15), M0
	VPERMQ  $57, S1, Y6
	VPXOR   S0, Y6, Y6
	VPAND   S2, S3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   M0, Y6, M0
	VMOVDQU M0, (R15)
	COPY(R10, R15, R9)
	MOVQ    $0, AX
	MOVQ    R15, DI
	MOVQ    $32, CX
	SUBQ    R9, CX
	ADDQ    R9, DI
	REP
	STOSB
	VMOVDQU (R15), M0
	STATE_UPDATE()

decryptDone:

	// Finalize and write the tag.
	MOVQ    a+56(FP), R8    // len(a) -> R8
	MOVQ    m+32(FP), R9    // len(m) -> R9
	MOVQ    tag+88(FP), R14 // tag -> R14
	VMOVDQU Y13, (R15)
	FINALIZE(R14, R8, R9, R15)

	VMOVDQU Y13, (R15)
	VZEROUPPER
	RET
