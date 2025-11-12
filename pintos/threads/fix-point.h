#ifndef THREADS_FIXPOINT_H
#define THREADS_FIXPOINT_H

/* Fixed-point arithmetic for MLFQS scheduler.
   Uses 17.14 fixed-point representation */

#define FP_SHIFT 14                    /* Number of fractional bits */
#define FP_F (1 << FP_SHIFT)           /* Fixed-point 1.0 (16384) */

/* Convert fixed-point to integer (rounding to nearest) */
#define FP_TO_INT_ROUND(X) ((X) >= 0 ? (((X) + (FP_F / 2)) >> FP_SHIFT) \
                                      : (((X) - (FP_F / 2)) >> FP_SHIFT))

/* Fixed-point addition/subtraction */
#define FP_ADD(X, Y) ((X) + (Y))
#define FP_SUB(X, Y) ((X) - (Y))

/* Fixed-point multiplication
 X (고정소수점) = 실제값 a × 2^14
 Y (고정소수점) = 실제값 b × 2^14
 X * Y = (a × 2^14) × (b × 2^14)
       = (a × b) × 2^28  ← 스케일이 2^28로 2배!
 */
#define FP_MULT(X, Y) ((((int64_t)(X)) * (Y)) >> FP_SHIFT)

#define FP_DIV(X, Y) ((((int64_t)(X)) * FP_F) / (Y))



/* Fixed-point and integer operations
 * F = Fixed-pointe I = INT
 */
#define FP_ADD_INT(F, I) ((F) + (I) * FP_F)
#define FP_SUB_INT(F, I) ((F) - (I) * FP_F)
#define FP_MULT_INT(F, I) ((F) * (I))
#define FP_DIV_INT(F, I) ((F) / (I))



#endif /* threads/fixpoint.h */
