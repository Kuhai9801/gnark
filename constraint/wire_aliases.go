// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import "math"

// WireAliasResolver resolves wire aliases during final constraint-system
// canonicalization.
type WireAliasResolver struct {
	Wire         func(uint32) uint32
	HasConstants bool
	Constant     func(uint32) (uint32, bool)
	AddCoeff     func(uint32, uint32) uint32
	MulCoeff     func(uint32, uint32) uint32
}

// ApplyWireAliases rewrites stored proof-relevant wire references in place,
// compacts eliminated internal wires, and rebuilds the instruction tree.
func (system *System) ApplyWireAliases(resolver WireAliasResolver, genericSparseID BlueprintID, eliminated []uint32) {
	if resolver.Wire == nil || (resolver.HasConstants && resolver.Constant == nil) {
		return
	}

	oldNbInternal := system.NbInternalVariables
	internalOffset := uint32(system.GetNbPublicVariables() + system.GetNbSecretVariables())
	compact, compactBoundary, newNbInternal := internalCompactor(internalOffset, oldNbInternal, eliminated)

	system.NbInternalVariables = newNbInternal
	system.lbWireLevel = make([]Level, system.NbInternalVariables)
	for i := range system.lbWireLevel {
		system.lbWireLevel[i] = LevelUnset
	}
	system.Levels = system.Levels[:0]

	nbConstraints := 0
	for i, pi := range system.Instructions {
		inst := pi.Unpack(system)
		bID := pi.BlueprintID
		blueprint := system.Blueprints[bID]

		switch b := blueprint.(type) {
		case BlueprintR1C:
			rewriteR1CCalldata(inst.Calldata, resolver, compact)

		case BlueprintSparseR1C:
			var c SparseR1C
			b.DecompressSparseR1C(&c, inst)
			rewriteSparseR1C(&c, resolver, compact)
			if system.Type == SystemSparseR1CS && !sparseFitsBlueprint(system, blueprint, c) {
				bID = genericSparseID
				b = system.Blueprints[bID].(BlueprintSparseR1C)
				pi.StartCallData = uint64(len(system.CallData))
				b.CompressSparseR1C(&c, &system.CallData)
			} else {
				writeSparseR1CInPlace(c, inst.Calldata, blueprint)
			}

		case BlueprintHint:
			rewriteHintCalldata(inst.Calldata, resolver, compact)

		case *BlueprintBatchInverse[U64], *BlueprintBatchInverse[U32]:
			rewriteBatchInverseCalldata(inst.Calldata, resolver, compact)

		default:
		}

		pi.BlueprintID = bID
		pi.ConstraintOffset = uint32(nbConstraints)
		pi.WireOffset = compactBoundary(pi.WireOffset)
		nbConstraints += system.Blueprints[bID].NbConstraints()
		system.Instructions[i] = pi

		level := system.Blueprints[bID].UpdateInstructionTree(pi.Unpack(system), system)
		system.appendInstructionToLevel(uint32(i), level)
	}

	system.NbConstraints = nbConstraints
	system.compactCommitments(compact)
	rewriteLogEntries(system.Logs, resolver, compact)
	rewriteLogEntries(system.DebugInfo, resolver, compact)
}

func rewriteLinearExpression(l LinearExpression, resolver WireAliasResolver, compact func(uint32) uint32) {
	for i := range l {
		if l[i].IsConstant() {
			continue
		}
		if resolver.HasConstants {
			if cID, ok := resolver.Constant(l[i].VID); ok {
				l[i].CID = resolver.MulCoeff(l[i].CID, cID)
				l[i].VID = math.MaxUint32
				continue
			}
		}
		l[i].VID = compact(resolver.Wire(l[i].VID))
	}
}

func rewriteR1CCalldata(calldata []uint32, resolver WireAliasResolver, compact func(uint32) uint32) {
	lenL := int(calldata[1])
	lenR := int(calldata[2])
	lenO := int(calldata[3])

	j := 4
	j = rewriteTermPairsCalldata(calldata, j, lenL, resolver, compact, 0)
	j = rewriteTermPairsCalldata(calldata, j, lenR, resolver, compact, 0)
	rewriteTermPairsCalldata(calldata, j, lenO, resolver, compact, 0)
}

func rewriteSparseR1C(c *SparseR1C, resolver WireAliasResolver, compact func(uint32) uint32) {
	if !resolver.HasConstants {
		c.XA = compact(resolver.Wire(c.XA))
		c.XB = compact(resolver.Wire(c.XB))
		c.XC = compact(resolver.Wire(c.XC))
		return
	}

	xa := resolvedSparseWire(c.XA, resolver, compact)
	xb := resolvedSparseWire(c.XB, resolver, compact)
	xc := resolvedSparseWire(c.XC, resolver, compact)

	if c.QM != CoeffIdZero {
		switch {
		case xa.isConstant && xb.isConstant:
			c.QC = resolver.AddCoeff(c.QC, resolver.MulCoeff(c.QM, resolver.MulCoeff(xa.coeffID, xb.coeffID)))
			c.QM = CoeffIdZero
		case xa.isConstant:
			c.QR = resolver.AddCoeff(c.QR, resolver.MulCoeff(c.QM, xa.coeffID))
			c.QM = CoeffIdZero
		case xb.isConstant:
			c.QL = resolver.AddCoeff(c.QL, resolver.MulCoeff(c.QM, xb.coeffID))
			c.QM = CoeffIdZero
		}
	}

	if c.QL != CoeffIdZero {
		if xa.isConstant {
			c.QC = resolver.AddCoeff(c.QC, resolver.MulCoeff(c.QL, xa.coeffID))
			c.QL = CoeffIdZero
		}
	}
	if c.QR != CoeffIdZero {
		if xb.isConstant {
			c.QC = resolver.AddCoeff(c.QC, resolver.MulCoeff(c.QR, xb.coeffID))
			c.QR = CoeffIdZero
		}
	}
	if c.QO != CoeffIdZero {
		if xc.isConstant {
			c.QC = resolver.AddCoeff(c.QC, resolver.MulCoeff(c.QO, xc.coeffID))
			c.QO = CoeffIdZero
		}
	}

	c.XA = xa.wireID
	c.XB = xb.wireID
	c.XC = xc.wireID
}

type sparseWire struct {
	wireID     uint32
	coeffID    uint32
	isConstant bool
}

func resolvedSparseWire(wire uint32, resolver WireAliasResolver, compact func(uint32) uint32) sparseWire {
	if cID, ok := resolver.Constant(wire); ok {
		return sparseWire{coeffID: cID, isConstant: true}
	}
	return sparseWire{wireID: compact(resolver.Wire(wire))}
}

func rewriteBatchInverseCalldata(calldata []uint32, resolver WireAliasResolver, compact func(uint32) uint32) {
	n := int(calldata[1])
	j := 2
	for i := 0; i < n; i++ {
		j = rewriteLinearExpressionCalldata(calldata, j, resolver, compact)
	}
}

func rewriteHintCalldata(calldata []uint32, resolver WireAliasResolver, compact func(uint32) uint32) {
	lenInputs := int(calldata[2])
	j := 3
	for i := 0; i < lenInputs; i++ {
		j = rewriteLinearExpressionCalldata(calldata, j, resolver, compact)
	}
	if calldata[j] != calldata[j+1] {
		start := compact(calldata[j])
		calldata[j+1] = start + calldata[j+1] - calldata[j]
		calldata[j] = start
	}
}

func rewriteLinearExpressionCalldata(calldata []uint32, j int, resolver WireAliasResolver, compact func(uint32) uint32) int {
	n := int(calldata[j])
	j++
	return rewriteTermPairsCalldata(calldata, j, n, resolver, compact, math.MaxUint32)
}

func rewriteTermPairsCalldata(calldata []uint32, j, n int, resolver WireAliasResolver, compact func(uint32) uint32, constantWire uint32) int {
	for k := 0; k < n; k++ {
		cID := j
		j++
		vID := j
		if calldata[vID] != math.MaxUint32 {
			if resolver.HasConstants {
				if constID, ok := resolver.Constant(calldata[vID]); ok {
					calldata[cID] = resolver.MulCoeff(calldata[cID], constID)
					calldata[vID] = constantWire
					j++
					continue
				}
			}
			calldata[vID] = compact(resolver.Wire(calldata[vID]))
		}
		j++
	}
	return j
}

func sparseFitsBlueprint(system *System, blueprint Blueprint, c SparseR1C) bool {
	switch blueprint.(type) {
	case *BlueprintGenericSparseR1C[U64], *BlueprintGenericSparseR1C[U32]:
		return true
	case *BlueprintSparseR1CMul[U64], *BlueprintSparseR1CMul[U32]:
		return c.Commitment == NOT &&
			c.QL == CoeffIdZero &&
			c.QR == CoeffIdZero &&
			c.QO == CoeffIdMinusOne &&
			c.QM != CoeffIdZero &&
			c.QC == CoeffIdZero
	case *BlueprintSparseR1CAdd[U64], *BlueprintSparseR1CAdd[U32]:
		return c.Commitment == NOT &&
			c.QO == CoeffIdMinusOne &&
			c.QM == CoeffIdZero
	case *BlueprintSparseR1CBool[U64], *BlueprintSparseR1CBool[U32]:
		return c.Commitment == NOT &&
			c.XA == c.XB &&
			c.QR == CoeffIdZero &&
			c.QO == CoeffIdZero &&
			c.QC == CoeffIdZero
	default:
		return false
	}
}

func writeSparseR1CInPlace(c SparseR1C, calldata []uint32, blueprint Blueprint) {
	switch blueprint.(type) {
	case *BlueprintGenericSparseR1C[U64], *BlueprintGenericSparseR1C[U32]:
		calldata[0] = c.XA
		calldata[1] = c.XB
		calldata[2] = c.XC
		calldata[3] = c.QL
		calldata[4] = c.QR
		calldata[5] = c.QO
		calldata[6] = c.QM
		calldata[7] = c.QC
		calldata[8] = uint32(c.Commitment)
	case *BlueprintSparseR1CMul[U64], *BlueprintSparseR1CMul[U32]:
		calldata[0] = c.XA
		calldata[1] = c.XB
		calldata[2] = c.XC
		calldata[3] = c.QM
	case *BlueprintSparseR1CAdd[U64], *BlueprintSparseR1CAdd[U32]:
		calldata[0] = c.XA
		calldata[1] = c.XB
		calldata[2] = c.XC
		calldata[3] = c.QL
		calldata[4] = c.QR
		calldata[5] = c.QC
	case *BlueprintSparseR1CBool[U64], *BlueprintSparseR1CBool[U32]:
		calldata[0] = c.XA
		calldata[1] = c.QL
		calldata[2] = c.QM
	}
}

func internalCompactor(offset uint32, nbInternal int, eliminated []uint32) (func(uint32) uint32, func(uint32) uint32, int) {
	if len(eliminated) == 0 {
		identity := func(v uint32) uint32 { return v }
		return identity, identity, nbInternal
	}
	removed := make([]bool, nbInternal)
	for _, wire := range eliminated {
		if wire < offset {
			continue
		}
		idx := int(wire - offset)
		if idx >= 0 && idx < nbInternal {
			removed[idx] = true
		}
	}
	removedBefore := make([]uint32, nbInternal+1)
	for i, isRemoved := range removed {
		removedBefore[i+1] = removedBefore[i]
		if isRemoved {
			removedBefore[i+1]++
		}
	}
	compactBoundary := func(v uint32) uint32 {
		if v <= offset {
			return v
		}
		idx := int(v - offset)
		if idx > nbInternal {
			idx = nbInternal
		}
		return v - removedBefore[idx]
	}
	compact := func(v uint32) uint32 {
		if v < offset {
			return v
		}
		idx := int(v - offset)
		if idx < 0 || idx >= nbInternal {
			return compactBoundary(v)
		}
		return v - removedBefore[idx]
	}
	return compact, compactBoundary, nbInternal - int(removedBefore[nbInternal])
}

func (system *System) compactCommitments(compact func(uint32) uint32) {
	switch commitments := system.CommitmentInfo.(type) {
	case Groth16Commitments:
		for i := range commitments {
			compactInts(commitments[i].PublicAndCommitmentCommitted, compact)
			compactInts(commitments[i].PrivateCommitted, compact)
			commitments[i].CommitmentIndex = int(compact(uint32(commitments[i].CommitmentIndex)))
		}
		system.CommitmentInfo = commitments
	}
}

func compactInts(values []int, compact func(uint32) uint32) {
	for i, v := range values {
		values[i] = int(compact(uint32(v)))
	}
}

func rewriteLogEntries(entries []LogEntry, resolver WireAliasResolver, compact func(uint32) uint32) {
	for i := range entries {
		for j := range entries[i].ToResolve {
			rewriteLinearExpression(entries[i].ToResolve[j], resolver, compact)
		}
	}
}

func (system *System) appendInstructionToLevel(iID uint32, level Level) {
	if level < 0 {
		level = 0
	}
	if int(level) >= len(system.Levels) {
		system.Levels = append(system.Levels, []uint32{iID})
		return
	}
	system.Levels[level] = append(system.Levels[level], iID)
}
