#ifndef THREADS_FIXPOINT_H
#define THREADS_FIXPOINT_H

/* Fixed-point arithmetic for MLFQS scheduler.
   Uses 17.14 fixed-point representation */

#define FP_SHIFT 14                    /* Number of fractional bits */
#define FP_F (1 << FP_SHIFT)           /* Fixed-point 1.0 (16384) */

/* Convert fixed-point to integer (rounding to nearest) */
#define FP_TO_INT_ROUND(X) ((X) >= 0 ? (((X) + (FP_F / 2)) >> FP_SHIFT) \
                                      : (((X) - (FP_F / 2)) >> FP_SHIFT))

#endif /* threads/fixpoint.h */
