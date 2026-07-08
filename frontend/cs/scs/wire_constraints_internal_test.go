package scs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

// newTestBuilder creates a fresh SCS builder for internal tests.
func newTestBuilder(t *testing.T) *builder[constraint.U64] {
	t.Helper()
	b, err := NewBuilder[constraint.U64](ecc.BN254.ScalarField(), frontend.CompileConfig{Capacity: 100})
	if err != nil {
		t.Fatal(err)
	}
	return b.(*builder[constraint.U64])
}

func secretLeaf(name string) schema.LeafInfo {
	return schema.LeafInfo{FullName: func() string { return name }, Visibility: schema.Secret}
}

func publicLeaf(name string) schema.LeafInfo {
	return schema.LeafInfo{FullName: func() string { return name }, Visibility: schema.Public}
}

// TestGetWireConstraints_InternalToInputAlias verifies that GetWireConstraints
// correctly finds a producer constraint whose raw wire ID differs from the
// canonical representative after an internal-to-input alias is established.
func TestGetWireConstraints_InternalToInputAlias(t *testing.T) {
	b := newTestBuilder(t)

	// Create public input first to ensure proper wire numbering.
	pub := b.PublicVariable(publicLeaf("Pub"))

	// Create secret inputs and an internal wire produced by a constraint.
	a := b.SecretVariable(secretLeaf("A"))
	bVar := b.SecretVariable(secretLeaf("B"))
	prod := b.Mul(a, bVar) // internal wire, constraint stored with raw internal VID

	// Alias the internal wire to the public input.
	b.AssertIsEqual(prod, pub) // Union(internalVID, pubVID), internal aliases to pub

	// Now query the internal wire through GetWireConstraints.
	// Before the fix, canonicalTerm would return pubVID, but the stored
	// constraint still references the raw internal VID, causing a miss.
	pairs, err := b.GetWireConstraints([]frontend.Variable{prod}, false)
	if err != nil {
		t.Fatalf("GetWireConstraints(addMissing=false) failed: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 constraint pair, got %d", len(pairs))
	}
	// The constraint should be found; location depends on constraint shape.
	if loc := pairs[0][1]; loc < 0 || loc > 2 {
		t.Fatalf("expected wire location in [0,2], got %d", loc)
	}
	t.Logf("found wire at constraint %d location %d", pairs[0][0], pairs[0][1])

	// Also verify addMissing=true doesn't add a redundant identity constraint.
	pairs2, err := b.GetWireConstraints([]frontend.Variable{prod}, true)
	if err != nil {
		t.Fatalf("GetWireConstraints(addMissing=true) failed: %v", err)
	}
	if len(pairs2) != 1 {
		t.Fatalf("expected 1 constraint pair with addMissing=true, got %d", len(pairs2))
	}
}

// TestGetWiresConstraintExact_InternalToInputAlias verifies that
// GetWiresConstraintExact correctly maps each requested wire (including
// duplicates) to its producer constraint position when aliases are active.
func TestGetWiresConstraintExact_InternalToInputAlias(t *testing.T) {
	b := newTestBuilder(t)

	a := b.SecretVariable(secretLeaf("A"))
	bVar := b.SecretVariable(secretLeaf("B"))
	prod := b.Mul(a, bVar) // internal wire

	pub := b.PublicVariable(publicLeaf("Pub"))
	b.AssertIsEqual(prod, pub) // internal aliases to pub

	// Query with duplicates to exercise the exact (non-deduplicating) path.
	pairs, err := b.GetWiresConstraintExact([]frontend.Variable{prod, prod, pub}, false)
	if err != nil {
		t.Fatalf("GetWiresConstraintExact failed: %v", err)
	}
	if len(pairs) != 3 {
		t.Fatalf("expected 3 exact pairs, got %d", len(pairs))
	}
	// All three should map to the same constraint position (the Mul producer).
	first := pairs[0]
	for i := 1; i < len(pairs); i++ {
		if pairs[i] != first {
			t.Fatalf("expected all pairs to share the same constraint position, got %v vs %v", first, pairs[i])
		}
	}

	// addMissing=true with duplicates.
	pairs2, err := b.GetWiresConstraintExact([]frontend.Variable{prod, pub, prod}, true)
	if err != nil {
		t.Fatalf("GetWiresConstraintExact(addMissing=true) failed: %v", err)
	}
	if len(pairs2) != 3 {
		t.Fatalf("expected 3 exact pairs with addMissing=true, got %d", len(pairs2))
	}
}

// TestGetWireConstraints_InternalToInternalAlias verifies lookups when both
// sides of the alias are internal wires.
func TestGetWireConstraints_InternalToInternalAlias(t *testing.T) {
	b := newTestBuilder(t)

	a := b.SecretVariable(secretLeaf("A"))
	bVar := b.SecretVariable(secretLeaf("B"))
	prod1 := b.Mul(a, bVar) // internal wire 1

	c := b.SecretVariable(secretLeaf("C"))
	d := b.SecretVariable(secretLeaf("D"))
	prod2 := b.Mul(c, d) // internal wire 2

	b.AssertIsEqual(prod1, prod2) // Union(internal1, internal2), one eliminated

	// Query the eliminated wire's canonical representative.
	pairs, err := b.GetWireConstraints([]frontend.Variable{prod1}, false)
	if err != nil {
		t.Fatalf("GetWireConstraints failed for internal-to-internal alias: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected 1 constraint pair, got %d", len(pairs))
	}
}
