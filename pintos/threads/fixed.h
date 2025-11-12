// fixed.h
#pragma once
#include <stdint.h>

#define FP_SHIFT 14
#define FP ((int64_t)1 << FP_SHIFT)

/* int <-> fixed */
static inline int64_t itof(int n) { return (int64_t)n * FP; }
static inline int ftoi_trunc(int64_t x) { return (int)(x / FP); }
static inline int ftoi_round(int64_t x) { return (int)((x >= 0) ? (x + FP / 2) / FP : (x - FP / 2) / FP); }

/* fixed ops: 64비트만 사용 */
static inline int64_t fadd(int64_t x, int64_t y) { return x + y; }
static inline int64_t fsub(int64_t x, int64_t y) { return x - y; }

/* 곱셈/나눗셈: 64비트 스케일 방식 */
static inline int64_t fmul(int64_t x, int64_t y) { return (x * y) / FP; }
static inline int64_t fmul_i(int64_t x, int n) { return x * (int64_t)n; }
static inline int64_t fdiv(int64_t x, int64_t y) { return (x * FP) / y; }
static inline int64_t fdiv_i(int64_t x, int n) { return x / (int64_t)n; }