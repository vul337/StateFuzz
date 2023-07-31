#ifndef _CRANGE_H
#define _CRANGE_H

#pragma once

#include <llvm/IR/ConstantRange.h>

// llvm::ConstantRange fixup.
class CRange : public llvm::ConstantRange {
	typedef llvm::APInt APInt;
	typedef llvm::ConstantRange super;
public:
	CRange(uint32_t BitWidth, bool isFullSet) : super(BitWidth, isFullSet) {}
	// Constructors.
	CRange(const super &CR) : super(CR) {}
	CRange(const APInt &Value)
		: super(Value) {}
	CRange(const APInt &Lower, const APInt &Upper)
		: super(Lower, Upper) {}
	static CRange makeFullSet(uint32_t BitWidth) {
		return CRange(BitWidth, true);
	}
	static CRange makeEmptySet(uint32_t BitWidth) {
		return CRange(BitWidth, false);
	}
	static CRange makeICmpRegion(llvm::CmpInst::Predicate Pred, const CRange &other) {
		return super::makeAllowedICmpRegion(Pred, other);
	}

	void match(const CRange &R) {
		if (this->getBitWidth() != R.getBitWidth()) {
			llvm::errs() << "warning: range " << *this << " " 
				<< this->getBitWidth() << " and " << R << " "
				<< R.getBitWidth() << " unmatch\n";
			*this = this->zextOrTrunc(R.getBitWidth());
		}
	}

	bool safeUnion(const CRange &R) {
		CRange V = R, Old = *this;
		V.match(*this);
		*this = this->unionWith(V);
		return Old != *this;
	}


	CRange sdiv(const CRange &RHS) const {
		if (isEmptySet() || RHS.isEmptySet())
			return makeEmptySet(getBitWidth());
		// FIXME: too conservative.
		return makeFullSet(getBitWidth());
	}

};
#endif
