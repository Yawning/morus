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

DATA ·init_ones<>+0x00(SB)/8, $0xffffffffffffffff
DATA ·init_ones<>+0x08(SB)/8, $0xffffffffffffffff
DATA ·init_ones<>+0x10(SB)/8, $0xffffffffffffffff
DATA ·init_ones<>+0x18(SB)/8, $0xffffffffffffffff
GLOBL ·init_ones<>(SB), (NOPTR+RODATA), $32

// TODO: Think about instruction scheduling.
#define STATE_UPDATE(S0, S1, S2, S3, S4, M0, T0, T1) \
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

// func initAVX2(s *uint64, key, iv *byte, initConsts *uint64)
TEXT ·initAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ key+8(FP), R9
	MOVQ iv+16(FP), R10
	MOVQ initConsts+24(FP), R11

	VPXOR   Y0, Y0, Y0
	MOVOU   (R10), X0
	VMOVDQU (R9), Y1
	VMOVDQU ·init_ones<>(SB), Y2
	VPXOR   Y3, Y3, Y3
	VMOVDQU (R11), Y4

	VPXOR   Y5, Y5, Y5
	VMOVDQA Y1, Y6

	MOVQ $16, AX

initloop:
	STATE_UPDATE(Y0, Y1, Y2, Y3, Y4, Y5, Y14, Y15)

	SUBQ $1, AX
	JNZ  initloop

	VPXOR Y6, Y1, Y1

	VMOVDQU Y0, (R8)
	VMOVDQU Y1, 32(R8)
	VMOVDQU Y2, 64(R8)
	VMOVDQU Y3, 96(R8)
	VMOVDQU Y4, 128(R8)

	VZEROUPPER
	RET

// func absorbBlocksAVX2(s *uint64, in *byte, blocks uint64)
TEXT ·absorbBlocksAVX2(SB), NOSPLIT, $0-24
	MOVQ s+0(FP), R8
	MOVQ in+8(FP), R10
	MOVQ blocks+16(FP), R11

	VMOVDQU (R8), Y0
	VMOVDQU 32(R8), Y1
	VMOVDQU 64(R8), Y2
	VMOVDQU 96(R8), Y3
	VMOVDQU 128(R8), Y4

loopblocks:
	VMOVDQU (R10), Y5
	STATE_UPDATE(Y0, Y1, Y2, Y3, Y4, Y5, Y14, Y15)

	ADDQ $32, R10

	SUBQ $1, R11
	JNZ  loopblocks

	VMOVDQU Y0, (R8)
	VMOVDQU Y1, 32(R8)
	VMOVDQU Y2, 64(R8)
	VMOVDQU Y3, 96(R8)
	VMOVDQU Y4, 128(R8)

	VZEROUPPER
	RET

// func encryptBlocksAVX2(s *uint64, out, in *byte, blocks uint64)
TEXT ·encryptBlocksAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ out+8(FP), R9
	MOVQ in+16(FP), R10
	MOVQ blocks+24(FP), R11

	VMOVDQU (R8), Y0
	VMOVDQU 32(R8), Y1
	VMOVDQU 64(R8), Y2
	VMOVDQU 96(R8), Y3
	VMOVDQU 128(R8), Y4

loopblocks:
	VMOVDQU (R10), Y5

	VPERMQ  $57, Y1, Y6
	VPXOR   Y0, Y6, Y6
	VPAND   Y2, Y3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   Y5, Y6, Y6
	VMOVDQU Y6, (R9)

	STATE_UPDATE(Y0, Y1, Y2, Y3, Y4, Y5, Y14, Y15)

	ADDQ $32, R9
	ADDQ $32, R10

	SUBQ $1, R11
	JNZ  loopblocks

	VMOVDQU Y0, (R8)
	VMOVDQU Y1, 32(R8)
	VMOVDQU Y2, 64(R8)
	VMOVDQU Y3, 96(R8)
	VMOVDQU Y4, 128(R8)

	VZEROUPPER
	RET

// func decryptBlocksAVX2(s *uint64, out, in *byte, blocks uint64)
TEXT ·decryptBlocksAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ out+8(FP), R9
	MOVQ in+16(FP), R10
	MOVQ blocks+24(FP), R11

	VMOVDQU (R8), Y0
	VMOVDQU 32(R8), Y1
	VMOVDQU 64(R8), Y2
	VMOVDQU 96(R8), Y3
	VMOVDQU 128(R8), Y4

loopblocks:
	VMOVDQU (R10), Y5

	VPERMQ  $57, Y1, Y6
	VPXOR   Y0, Y6, Y6
	VPAND   Y2, Y3, Y7
	VPXOR   Y6, Y7, Y6
	VPXOR   Y5, Y6, Y5
	VMOVDQU Y5, (R9)

	STATE_UPDATE(Y0, Y1, Y2, Y3, Y4, Y5, Y14, Y15)

	ADDQ $32, R9
	ADDQ $32, R10

	SUBQ $1, R11
	JNZ  loopblocks

	VMOVDQU Y0, (R8)
	VMOVDQU Y1, 32(R8)
	VMOVDQU Y2, 64(R8)
	VMOVDQU Y3, 96(R8)
	VMOVDQU Y4, 128(R8)

	VZEROUPPER
	RET

// func decryptLastBlockAVX2(s *uint64, out, in *byte, mask *uint64)
TEXT ·decryptLastBlockAVX2(SB), NOSPLIT, $0-32
	MOVQ s+0(FP), R8
	MOVQ out+8(FP), R9
	MOVQ in+16(FP), R10
	MOVQ mask+24(FP), R11

	VMOVDQU (R8), Y0
	VMOVDQU 32(R8), Y1
	VMOVDQU 64(R8), Y2
	VMOVDQU 96(R8), Y3
	VMOVDQU 128(R8), Y4

	VMOVDQU (R10), Y5

	VPERMQ $57, Y1, Y6
	VPXOR  Y0, Y6, Y6
	VPAND  Y2, Y3, Y7
	VPXOR  Y6, Y7, Y6
	VPXOR  Y5, Y6, Y5

	VMOVDQU (R11), Y6
	VPAND   Y5, Y6, Y5
	VMOVDQU Y5, (R9)

	STATE_UPDATE(Y0, Y1, Y2, Y3, Y4, Y5, Y14, Y15)

	VMOVDQU Y0, (R8)
	VMOVDQU Y1, 32(R8)
	VMOVDQU Y2, 64(R8)
	VMOVDQU Y3, 96(R8)
	VMOVDQU Y4, 128(R8)

	VZEROUPPER
	RET

// func finalizeAVX2(s *uint64, tag *byte, lastBlock *uint64)
TEXT ·finalizeAVX2(SB), NOSPLIT, $0-24
	MOVQ s+0(FP), R8
	MOVQ tag+8(FP), R9
	MOVQ lastBlock+16(FP), R10

	VMOVDQU (R8), Y0
	VMOVDQU 32(R8), Y1
	VMOVDQU 64(R8), Y2
	VMOVDQU 96(R8), Y3
	VMOVDQU 128(R8), Y4

	VPXOR Y4, Y0, Y4

	VMOVDQU (R10), Y5
	MOVQ    $10, AX

finalloop:
	STATE_UPDATE(Y0, Y1, Y2, Y3, Y4, Y5, Y14, Y15)

	SUBQ $1, AX
	JNZ  finalloop

	VPERMQ $57, Y1, Y6
	VPXOR  Y0, Y6, Y6
	VPAND  Y2, Y3, Y7
	VPXOR  Y6, Y7, Y5

	MOVOU X5, (R9)

	VZEROUPPER
	RET
