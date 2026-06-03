package wirealias

import "testing"

func TestMarkNoAliasAfterUnionInvalidatesAliasSet(t *testing.T) {
	var s Set
	s.MarkInternal(1)
	s.MarkInternal(2)
	if !s.Union(1, 2) {
		t.Fatal("expected internal wires to alias")
	}
	s.MarkNoAlias(2)

	if !s.Invalidated() {
		t.Fatal("expected late no-alias marker to invalidate alias set")
	}
	if got := s.Rep(2); got != 2 {
		t.Fatalf("expected no-alias wire to remain its own representative, got %d", got)
	}
	if eliminated := s.Eliminated(); len(eliminated) != 0 {
		t.Fatalf("expected no eliminated wires for no-alias class, got %v", eliminated)
	}
}

func TestMarkNoAliasOnRepresentativeDoesNotInvalidateAliasSet(t *testing.T) {
	var s Set
	s.MarkInternal(1)
	s.MarkInternal(2)
	if !s.Union(1, 2) {
		t.Fatal("expected internal wires to alias")
	}
	s.MarkNoAlias(1)

	if s.Invalidated() {
		t.Fatal("using the surviving representative should not invalidate alias set")
	}
	if got := s.Rep(2); got != 1 {
		t.Fatalf("expected eliminated wire to keep representative 1, got %d", got)
	}
	eliminated := s.Eliminated()
	if len(eliminated) != 1 || eliminated[0] != 2 {
		t.Fatalf("expected only eliminated member 2, got %v", eliminated)
	}
}

func TestMarkNoAliasBeforeUnionPreventsAlias(t *testing.T) {
	var s Set
	s.MarkInternal(1)
	s.MarkInternal(2)
	s.MarkNoAlias(2)

	if s.Invalidated() {
		t.Fatal("pre-union no-alias marker should not invalidate alias set")
	}
	if s.Union(1, 2) {
		t.Fatal("expected no-alias wire to reject union")
	}
}

func TestUnionPrefersLowerRepresentative(t *testing.T) {
	var s Set
	s.MarkInternal(1)
	s.MarkInternal(2)

	if !s.Union(1, 2) {
		t.Fatal("expected internal wires to alias")
	}
	if got := s.Rep(2); got != 1 {
		t.Fatalf("expected lower wire to be representative, got %d", got)
	}
}

func TestAliasToExternalWireEliminatesInternal(t *testing.T) {
	var s Set
	s.MarkNoAlias(1)
	s.MarkInternal(2)

	if !s.AliasToWire(2, 1) {
		t.Fatal("expected internal wire to alias to external wire")
	}
	if got := s.Rep(2); got != 1 {
		t.Fatalf("expected external wire representative, got %d", got)
	}
	eliminated := s.Eliminated()
	if len(eliminated) != 1 || eliminated[0] != 2 {
		t.Fatalf("expected internal wire 2 to be eliminated, got %v", eliminated)
	}
}

func TestAliasToConstantEliminatesInternal(t *testing.T) {
	var s Set
	s.MarkInternal(2)

	if !s.AliasToConstant(2, 42) {
		t.Fatal("expected internal wire to alias to constant")
	}
	if cID, ok := s.Constant(2); !ok || cID != 42 {
		t.Fatalf("expected constant alias 42, got %d %v", cID, ok)
	}
	eliminated := s.Eliminated()
	if len(eliminated) != 1 || eliminated[0] != 2 {
		t.Fatalf("expected internal wire 2 to be eliminated, got %v", eliminated)
	}
}

func TestMarkNoAliasAfterConstantAliasKeepsFallbackElimination(t *testing.T) {
	var s Set
	s.MarkInternal(2)
	if !s.AliasToConstant(2, 42) {
		t.Fatal("expected internal wire to alias to constant")
	}
	s.MarkNoAlias(2)

	if s.Invalidated() {
		t.Fatal("constant aliases can fall back to an explicit equality constraint")
	}
	eliminated := s.Eliminated()
	if len(eliminated) != 1 || eliminated[0] != 2 {
		t.Fatalf("expected constant-alias wire to remain eliminated for fallback equality, got %v", eliminated)
	}
}
