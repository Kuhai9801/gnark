package constraint

import (
	"math"
	"math/big"
	"testing"
)

func TestApplyWireAliasesRewritesLogAliasToConstant(t *testing.T) {
	system := NewSystem(big.NewInt(17), 0, SystemSparseR1CS)
	system.NbInternalVariables = 2
	system.Logs = []LogEntry{{
		ToResolve: []LinearExpression{{{CID: CoeffIdOne, VID: 1}}},
	}}
	system.DebugInfo = []LogEntry{{
		ToResolve: []LinearExpression{{{CID: CoeffIdTwo, VID: 1}}},
	}}

	system.ApplyWireAliases(WireAliasResolver{
		Wire:         func(v uint32) uint32 { return v },
		HasConstants: true,
		Constant: func(v uint32) (uint32, bool) {
			if v == 1 {
				return CoeffIdTwo, true
			}
			return 0, false
		},
		MulCoeff: func(a, b uint32) uint32 {
			if a == CoeffIdOne && b == CoeffIdTwo {
				return CoeffIdTwo
			}
			if a == CoeffIdTwo && b == CoeffIdTwo {
				return 7
			}
			t.Fatalf("unexpected coefficient multiplication %d * %d", a, b)
			return 0
		},
	}, 0, []uint32{1})

	logTerm := system.Logs[0].ToResolve[0][0]
	if logTerm.VID != math.MaxUint32 || logTerm.CID != CoeffIdTwo {
		t.Fatalf("expected log alias to become constant coeff 2, got coeff=%d wire=%d", logTerm.CID, logTerm.VID)
	}
	debugTerm := system.DebugInfo[0].ToResolve[0][0]
	if debugTerm.VID != math.MaxUint32 || debugTerm.CID != 7 {
		t.Fatalf("expected debug alias to become constant coeff 7, got coeff=%d wire=%d", debugTerm.CID, debugTerm.VID)
	}
}
