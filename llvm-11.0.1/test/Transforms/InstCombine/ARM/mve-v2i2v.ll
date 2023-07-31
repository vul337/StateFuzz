; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -instcombine -S -o - %s | FileCheck %s

target datalayout = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64"

declare i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1>)
declare i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1>)
declare i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1>)

declare <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32)
declare <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32)
declare <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32)

; Round-trip conversions from predicate vector to i32 back to the same
; size of vector should be eliminated.

define <4 x i1> @v2i2v_4(<4 x i1> %vin) {
; CHECK-LABEL: @v2i2v_4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret <4 x i1> [[VIN:%.*]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %int)
  ret <4 x i1> %vout
}

define <8 x i1> @v2i2v_8(<8 x i1> %vin) {
; CHECK-LABEL: @v2i2v_8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret <8 x i1> [[VIN:%.*]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1> %vin)
  %vout = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %int)
  ret <8 x i1> %vout
}

define <16 x i1> @v2i2v_16(<16 x i1> %vin) {
; CHECK-LABEL: @v2i2v_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret <16 x i1> [[VIN:%.*]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1> %vin)
  %vout = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %int)
  ret <16 x i1> %vout
}

; Conversions from a predicate vector to i32 and then to a _different_
; size of predicate vector should be left alone.

define <16 x i1> @v2i2v_4_16(<4 x i1> %vin) {
; CHECK-LABEL: @v2i2v_4_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[INT:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    [[VOUT:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[INT]])
; CHECK-NEXT:    ret <16 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %vout = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %int)
  ret <16 x i1> %vout
}

define <4 x i1> @v2i2v_8_4(<8 x i1> %vin) {
; CHECK-LABEL: @v2i2v_8_4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[INT:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    [[VOUT:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[INT]])
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1> %vin)
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %int)
  ret <4 x i1> %vout
}

define <8 x i1> @v2i2v_16_8(<16 x i1> %vin) {
; CHECK-LABEL: @v2i2v_16_8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[INT:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    [[VOUT:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[INT]])
; CHECK-NEXT:    ret <8 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1> %vin)
  %vout = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %int)
  ret <8 x i1> %vout
}

; Round-trip conversions from i32 to predicate vector back to i32
; should be eliminated.

define i32 @i2v2i_4(i32 %iin) {
; CHECK-LABEL: @i2v2i_4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 [[IIN:%.*]]
;
entry:
  %vec = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %iin)
  %iout = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vec)
  ret i32 %iout
}

define i32 @i2v2i_8(i32 %iin) {
; CHECK-LABEL: @i2v2i_8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 [[IIN:%.*]]
;
entry:
  %vec = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %iin)
  %iout = call i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1> %vec)
  ret i32 %iout
}

define i32 @i2v2i_16(i32 %iin) {
; CHECK-LABEL: @i2v2i_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 [[IIN:%.*]]
;
entry:
  %vec = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %iin)
  %iout = call i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1> %vec)
  ret i32 %iout
}

; v2i leaves the top 16 bits clear. So a trunc/zext pair applied to
; its output, going via i16, can be completely eliminated - but not
; one going via i8. Similarly with other methods of clearing the top
; bits, like bitwise and.

define i32 @v2i_truncext_i16(<4 x i1> %vin) {
; CHECK-LABEL: @v2i_truncext_i16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[WIDE1:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    ret i32 [[WIDE1]]
;
entry:
  %wide1 = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %narrow = trunc i32 %wide1 to i16
  %wide2 = zext i16 %narrow to i32
  ret i32 %wide2
}

define i32 @v2i_truncext_i8(<4 x i1> %vin) {
; CHECK-LABEL: @v2i_truncext_i8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[WIDE1:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    [[WIDE2:%.*]] = and i32 [[WIDE1]], 255
; CHECK-NEXT:    ret i32 [[WIDE2]]
;
entry:
  %wide1 = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %narrow = trunc i32 %wide1 to i8
  %wide2 = zext i8 %narrow to i32
  ret i32 %wide2
}

define i32 @v2i_and_16(<4 x i1> %vin) {
; CHECK-LABEL: @v2i_and_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[WIDE1:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    ret i32 [[WIDE1]]
;
entry:
  %wide1 = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %wide2 = and i32 %wide1, 65535
  ret i32 %wide2
}

define i32 @v2i_and_15(<4 x i1> %vin) {
; CHECK-LABEL: @v2i_and_15(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[WIDE1:%.*]] = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> [[VIN:%.*]]), !range !0
; CHECK-NEXT:    [[WIDE2:%.*]] = and i32 [[WIDE1]], 32767
; CHECK-NEXT:    ret i32 [[WIDE2]]
;
entry:
  %wide1 = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %wide2 = and i32 %wide1, 32767
  ret i32 %wide2
}

; i2v doesn't use the top bits of its input. So the same operations
; on a value that's about to be passed to i2v can be eliminated.

define <4 x i1> @i2v_truncext_i16(i32 %wide1) {
; CHECK-LABEL: @i2v_truncext_i16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[WIDE1:%.*]])
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %narrow = trunc i32 %wide1 to i16
  %wide2 = zext i16 %narrow to i32
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %wide2)
  ret <4 x i1> %vout
}

define <4 x i1> @i2v_truncext_i8(i32 %wide1) {
; CHECK-LABEL: @i2v_truncext_i8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[WIDE2:%.*]] = and i32 [[WIDE1:%.*]], 255
; CHECK-NEXT:    [[VOUT:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[WIDE2]])
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %narrow = trunc i32 %wide1 to i8
  %wide2 = zext i8 %narrow to i32
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %wide2)
  ret <4 x i1> %vout
}

define <4 x i1> @i2v_and_16(i32 %wide1) {
; CHECK-LABEL: @i2v_and_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[WIDE1:%.*]])
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %wide2 = and i32 %wide1, 65535
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %wide2)
  ret <4 x i1> %vout
}

define <4 x i1> @i2v_and_15(i32 %wide1) {
; CHECK-LABEL: @i2v_and_15(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[WIDE2:%.*]] = and i32 [[WIDE1:%.*]], 32767
; CHECK-NEXT:    [[VOUT:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[WIDE2]])
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %wide2 = and i32 %wide1, 32767
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %wide2)
  ret <4 x i1> %vout
}

; If a predicate vector is round-tripped to an integer and back, and
; complemented while it's in integer form, we should collapse that to
; a complement of the vector itself. (Rationale: this is likely to
; allow it to be code-generated as MVE VPNOT.)

define <4 x i1> @vpnot_4(<4 x i1> %vin) {
; CHECK-LABEL: @vpnot_4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = xor <4 x i1> [[VIN:%.*]], <i1 true, i1 true, i1 true, i1 true>
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %flipped = xor i32 %int, 65535
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %flipped)
  ret <4 x i1> %vout
}

define <8 x i1> @vpnot_8(<8 x i1> %vin) {
; CHECK-LABEL: @vpnot_8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = xor <8 x i1> [[VIN:%.*]], <i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true>
; CHECK-NEXT:    ret <8 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1> %vin)
  %flipped = xor i32 %int, 65535
  %vout = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %flipped)
  ret <8 x i1> %vout
}

define <16 x i1> @vpnot_16(<16 x i1> %vin) {
; CHECK-LABEL: @vpnot_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = xor <16 x i1> [[VIN:%.*]], <i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true>
; CHECK-NEXT:    ret <16 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1> %vin)
  %flipped = xor i32 %int, 65535
  %vout = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %flipped)
  ret <16 x i1> %vout
}

; And this still works even if the i32 is narrowed to i16 and back on
; opposite sides of the xor.

define <4 x i1> @vpnot_narrow_4(<4 x i1> %vin) {
; CHECK-LABEL: @vpnot_narrow_4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = xor <4 x i1> [[VIN:%.*]], <i1 true, i1 true, i1 true, i1 true>
; CHECK-NEXT:    ret <4 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1> %vin)
  %narrow = trunc i32 %int to i16
  %flipped_narrow = xor i16 %narrow, -1
  %flipped = zext i16 %flipped_narrow to i32
  %vout = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %flipped)
  ret <4 x i1> %vout
}

define <8 x i1> @vpnot_narrow_8(<8 x i1> %vin) {
; CHECK-LABEL: @vpnot_narrow_8(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = xor <8 x i1> [[VIN:%.*]], <i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true>
; CHECK-NEXT:    ret <8 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1> %vin)
  %narrow = trunc i32 %int to i16
  %flipped_narrow = xor i16 %narrow, -1
  %flipped = zext i16 %flipped_narrow to i32
  %vout = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %flipped)
  ret <8 x i1> %vout
}

define <16 x i1> @vpnot_narrow_16(<16 x i1> %vin) {
; CHECK-LABEL: @vpnot_narrow_16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[VOUT:%.*]] = xor <16 x i1> [[VIN:%.*]], <i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true, i1 true>
; CHECK-NEXT:    ret <16 x i1> [[VOUT]]
;
entry:
  %int = call i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1> %vin)
  %narrow = trunc i32 %int to i16
  %flipped_narrow = xor i16 %narrow, -1
  %flipped = zext i16 %flipped_narrow to i32
  %vout = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %flipped)
  ret <16 x i1> %vout
}
