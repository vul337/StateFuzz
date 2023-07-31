; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-linux -mattr=+sse2 | FileCheck %s

@atomic = global double 0.000000e+00		; <double*> [#uses=1]
@atomic2 = global double 0.000000e+00		; <double*> [#uses=1]
@anything = global i64 0		; <i64*> [#uses=1]
@ioport = global i32 0		; <i32*> [#uses=2]

define i16 @f(i64 %x, double %y) {
; CHECK-LABEL: f:
; CHECK:       # %bb.0:
; CHECK-NEXT:    movsd {{.*#+}} xmm0 = mem[0],zero
; CHECK-NEXT:    movsd {{.*#+}} xmm1 = mem[0],zero
; CHECK-NEXT:    movsd %xmm1, atomic
; CHECK-NEXT:    xorps %xmm1, %xmm1
; CHECK-NEXT:    movsd %xmm1, atomic2
; CHECK-NEXT:    movsd %xmm0, anything
; CHECK-NEXT:    movl ioport, %ecx
; CHECK-NEXT:    movl ioport, %eax
; CHECK-NEXT:    shrl $16, %eax
; CHECK-NEXT:    addl %ecx, %eax
; CHECK-NEXT:    # kill: def $ax killed $ax killed $eax
; CHECK-NEXT:    retl
	%b = bitcast i64 %x to double		; <double> [#uses=1]
	store volatile double %b, double* @atomic ; one processor operation only
	store volatile double 0.000000e+00, double* @atomic2 ; one processor operation only
	%b2 = bitcast double %y to i64		; <i64> [#uses=1]
	store volatile i64 %b2, i64* @anything ; may transform to store of double
	%l = load volatile i32, i32* @ioport		; must not narrow
	%t = trunc i32 %l to i16		; <i16> [#uses=1]
	%l2 = load volatile i32, i32* @ioport		; must not narrow
	%tmp = lshr i32 %l2, 16		; <i32> [#uses=1]
	%t2 = trunc i32 %tmp to i16		; <i16> [#uses=1]
	%f = add i16 %t, %t2		; <i16> [#uses=1]
	ret i16 %f
}
