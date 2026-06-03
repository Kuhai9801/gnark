package issue555

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
)

const nbEqualities = 16

type internalEqualityCircuit struct {
	WithEqualities bool `gnark:"-"`
	A, B           [nbEqualities]frontend.Variable
	C, D           [nbEqualities]frontend.Variable
}

func (c *internalEqualityCircuit) Define(api frontend.API) error {
	for i := 0; i < nbEqualities; i++ {
		left := api.Mul(c.A[i], c.B[i])
		right := api.Mul(c.C[i], c.D[i])
		if c.WithEqualities {
			api.AssertIsEqual(left, right)
		}
	}
	return nil
}

func TestInternalEqualitiesAreCanonicalized(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			base := compile(t, tc, &internalEqualityCircuit{})
			withEqualities := compile(t, tc, &internalEqualityCircuit{WithEqualities: true})

			baseConstraints := base.GetNbConstraints()
			withConstraints := withEqualities.GetNbConstraints()
			if baseConstraints != 32 {
				t.Fatalf("expected base circuit to have 32 constraints, got %d", baseConstraints)
			}
			if withConstraints != baseConstraints {
				t.Fatalf("expected internal equalities to be canonicalized, got base=%d withEqualities=%d", baseConstraints, withConstraints)
			}
			if want := base.GetNbInternalVariables() - nbEqualities; withEqualities.GetNbInternalVariables() != want {
				t.Fatalf("expected one internal wire eliminated per equality, got want=%d withEqualities=%d", want, withEqualities.GetNbInternalVariables())
			}

			validWitness, err := frontend.NewWitness(internalEqualityAssignment(false), tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := withEqualities.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve rewritten constraints: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(internalEqualityAssignment(true), tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := withEqualities.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail after rewriting stale pre-merge constraints")
			}
		})
	}
}

type inputEqualityCircuit struct {
	A, B frontend.Variable
	X    frontend.Variable `gnark:",public"`
}

func (c *inputEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.X)
	return nil
}

type secretInternalEqualityCircuit struct {
	A, B, X frontend.Variable
}

func (c *secretInternalEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.X)
	return nil
}

type constantInternalEqualityCircuit struct {
	A, B frontend.Variable
}

func (c *constantInternalEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), 6)
	return nil
}

type transitiveConstantInternalEqualityCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *transitiveConstantInternalEqualityCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	y := api.Mul(c.C, c.D)
	api.AssertIsEqual(x, 6)
	api.AssertIsEqual(x, y)
	return nil
}

type constantAliasCanonicalEscapeCircuit struct {
	A, B frontend.Variable
}

func (c *constantAliasCanonicalEscapeCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	api.AssertIsEqual(x, 6)
	api.Compiler().ToCanonicalVariable(x)
	return nil
}

func TestInternalInputAndConstantEqualitiesAreCanonicalized(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			cases := []struct {
				name       string
				circuit    frontend.Circuit
				assignment frontend.Circuit
				invalid    frontend.Circuit
			}{
				{"public", &inputEqualityCircuit{}, &inputEqualityCircuit{A: 2, B: 3, X: 6}, &inputEqualityCircuit{A: 2, B: 4, X: 6}},
				{"secret", &secretInternalEqualityCircuit{}, &secretInternalEqualityCircuit{A: 2, B: 3, X: 6}, &secretInternalEqualityCircuit{A: 2, B: 4, X: 6}},
				{"constant", &constantInternalEqualityCircuit{}, &constantInternalEqualityCircuit{A: 2, B: 3}, &constantInternalEqualityCircuit{A: 2, B: 4}},
			}
			for _, eq := range cases {
				t.Run(eq.name, func(t *testing.T) {
					ccs := compile(t, tc, eq.circuit)
					if got := ccs.GetNbConstraints(); got != 1 {
						t.Fatalf("expected internal %s equality to keep only the multiplication constraint, got %d", eq.name, got)
					}
					if got := ccs.GetNbInternalVariables(); got != 0 {
						t.Fatalf("expected internal %s equality to eliminate the multiplication output wire, got %d internal wires", eq.name, got)
					}
					witness, err := frontend.NewWitness(eq.assignment, tc.field)
					if err != nil {
						t.Fatal(err)
					}
					if err := ccs.IsSolved(witness); err != nil {
						t.Fatalf("valid witness should solve internal %s equality: %v", eq.name, err)
					}
					invalidWitness, err := frontend.NewWitness(eq.invalid, tc.field)
					if err != nil {
						t.Fatal(err)
					}
					if err := ccs.IsSolved(invalidWitness); err == nil {
						t.Fatalf("invalid witness should fail internal %s equality after canonicalization", eq.name)
					}
				})
			}
		})
	}
}

func TestConstantAliasCanonicalEscapeFallsBackToEquality(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc, &constantAliasCanonicalEscapeCircuit{})
			if got := ccs.GetNbConstraints(); got != 2 {
				t.Fatalf("expected multiplication plus fallback equality constraint, got %d", got)
			}
			if got := ccs.GetNbInternalVariables(); got != 1 {
				t.Fatalf("expected escaped internal wire to remain allocated, got %d internal wires", got)
			}

			validWitness, err := frontend.NewWitness(&constantAliasCanonicalEscapeCircuit{A: 2, B: 3}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid escaped constant-alias witness should solve: %v", err)
			}
			invalidWitness, err := frontend.NewWitness(&constantAliasCanonicalEscapeCircuit{A: 2, B: 4}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail escaped constant alias fallback equality")
			}
		})
	}
}

func TestTransitiveConstantInternalEqualitiesAreCanonicalized(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc, &transitiveConstantInternalEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 2 {
				t.Fatalf("expected two multiplication constraints and no equality constraint, got %d", got)
			}
			if got := ccs.GetNbInternalVariables(); got != 0 {
				t.Fatalf("expected both multiplication output wires to be eliminated, got %d internal wires", got)
			}
			validWitness, err := frontend.NewWitness(&transitiveConstantInternalEqualityCircuit{A: 2, B: 3, C: 1, D: 6}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve transitive constant alias circuit: %v", err)
			}
			invalidWitness, err := frontend.NewWitness(&transitiveConstantInternalEqualityCircuit{A: 2, B: 3, C: 1, D: 7}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail transitive constant alias circuit")
			}
		})
	}
}

type secretEqualityCircuit struct {
	A, B frontend.Variable
}

func (c *secretEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.A, c.B)
	return nil
}

func TestWitnessEqualityRemainsConstrained(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc, &secretEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 1 {
				t.Fatalf("expected witness equality to emit one constraint, got %d", got)
			}

			validWitness, err := frontend.NewWitness(&secretEqualityCircuit{A: 5, B: 5}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve witness equality: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(&secretEqualityCircuit{A: 5, B: 6}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail because witness equality remains constrained")
			}
		})
	}
}

type booleanBeforeAliasCircuit struct {
	X, A, B frontend.Variable
}

func (c *booleanBeforeAliasCircuit) Define(api frontend.API) error {
	b := api.IsZero(c.X)
	y := api.Mul(c.A, c.B)
	api.AssertIsEqual(b, y)
	if !api.Compiler().IsBoolean(y) {
		return fmt.Errorf("expected alias of boolean wire to be marked boolean")
	}
	return nil
}

type booleanAfterAliasCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *booleanAfterAliasCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	y := api.Mul(c.C, c.D)
	api.AssertIsEqual(x, y)
	api.Compiler().MarkBoolean(y)
	if !api.Compiler().IsBoolean(x) {
		return fmt.Errorf("expected boolean metadata marked after alias to canonicalize to alias class")
	}
	return nil
}

type booleanConstantAliasCircuit struct {
	A, B frontend.Variable
}

func (c *booleanConstantAliasCircuit) Define(api frontend.API) error {
	y := api.Mul(c.A, c.B)
	api.AssertIsEqual(y, 1)
	if !api.Compiler().IsBoolean(y) {
		return fmt.Errorf("expected internal wire aliased to constant one to be boolean")
	}
	return nil
}

func TestBooleanMetadataIsAliasAware(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			before := compile(t, tc, &booleanBeforeAliasCircuit{})
			beforeWitness, err := frontend.NewWitness(&booleanBeforeAliasCircuit{X: 0, A: 1, B: 1}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := before.IsSolved(beforeWitness); err != nil {
				t.Fatalf("valid before-alias boolean witness should solve: %v", err)
			}

			after := compile(t, tc, &booleanAfterAliasCircuit{})
			afterWitness, err := frontend.NewWitness(&booleanAfterAliasCircuit{A: 1, B: 1, C: 1, D: 1}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := after.IsSolved(afterWitness); err != nil {
				t.Fatalf("valid after-alias boolean witness should solve: %v", err)
			}

			constant := compile(t, tc, &booleanConstantAliasCircuit{})
			constantWitness, err := frontend.NewWitness(&booleanConstantAliasCircuit{A: 1, B: 1}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := constant.IsSolved(constantWitness); err != nil {
				t.Fatalf("valid constant-alias boolean witness should solve: %v", err)
			}
		})
	}
}

type opaqueInstructionCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *opaqueInstructionCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	y := api.Mul(c.C, c.D)
	compiler := api.Compiler()
	bID := compiler.AddBlueprint(noOpBlueprint{})
	compiler.AddInstruction(bID, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	api.AssertIsEqual(x, y)
	return nil
}

type noOpBlueprint struct{}

func (noOpBlueprint) CalldataSize() int {
	return 10
}

func (noOpBlueprint) NbConstraints() int {
	return 0
}

func (noOpBlueprint) NbOutputs(constraint.Instruction) int {
	return 0
}

func (noOpBlueprint) UpdateInstructionTree(constraint.Instruction, constraint.InstructionTree) constraint.Level {
	return 0
}

func TestOpaqueInstructionCalldataDisablesAliasing(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc, &opaqueInstructionCircuit{})
			if got := ccs.GetNbConstraints(); got != 3 {
				t.Fatalf("expected opaque instruction calldata to keep two multiplications and one equality constraint, got %d", got)
			}
			validWitness, err := frontend.NewWitness(&opaqueInstructionCircuit{A: 2, B: 3, C: 1, D: 6}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve opaque instruction circuit: %v", err)
			}
			invalidWitness, err := frontend.NewWitness(&opaqueInstructionCircuit{A: 2, B: 3, C: 1, D: 7}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail because escaped internal equality remains constrained")
			}
		})
	}
}

type lateOpaqueInstructionCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *lateOpaqueInstructionCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	y := api.Mul(c.C, c.D)
	api.AssertIsEqual(x, y)
	compiler := api.Compiler()
	bID := compiler.AddBlueprint(noOpBlueprint{})
	compiler.AddInstruction(bID, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	return nil
}

func TestLateOpaqueInstructionCalldataFailsClosed(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.compileErr(&lateOpaqueInstructionCircuit{})
			if err == nil {
				t.Fatal("expected compilation to fail when an aliased wire later escapes through opaque calldata")
			}
			if !strings.Contains(err.Error(), "wire alias invalidated") {
				t.Fatalf("expected wire-alias invalidation error, got %v", err)
			}
		})
	}
}

type blueprintStateAfterAliasCircuit struct {
	A, B, C, D frontend.Variable
	E, F       frontend.Variable
}

func (c *blueprintStateAfterAliasCircuit) Define(api frontend.API) error {
	x := api.Mul(c.A, c.B)
	y := api.Mul(c.C, c.D)
	api.AssertIsEqual(x, y)

	z := api.Mul(c.E, c.F)
	compiler := api.Compiler()
	var entry []uint32
	compiler.ToCanonicalVariable(z).Compress(&entry)
	var bID constraint.BlueprintID
	if constraint.FitsElement[constraint.U32](compiler.Field()) {
		bID = compiler.AddBlueprint(&rawWireStateBlueprint[constraint.U32]{Entry: entry})
	} else {
		bID = compiler.AddBlueprint(&rawWireStateBlueprint[constraint.U64]{Entry: entry})
	}
	outputs := compiler.AddInstruction(bID, nil)
	if len(outputs) != 1 {
		return fmt.Errorf("expected one raw-wire state output, got %d", len(outputs))
	}
	out := compiler.InternalVariable(outputs[0])
	api.AssertIsEqual(out, z)
	return nil
}

type rawWireStateBlueprint[E constraint.Element] struct {
	Entry []uint32
}

func (b *rawWireStateBlueprint[E]) CalldataSize() int {
	return 0
}

func (b *rawWireStateBlueprint[E]) NbConstraints() int {
	return 0
}

func (b *rawWireStateBlueprint[E]) NbOutputs(constraint.Instruction) int {
	return 1
}

func (b *rawWireStateBlueprint[E]) UpdateInstructionTree(inst constraint.Instruction, tree constraint.InstructionTree) constraint.Level {
	maxLevel := constraint.LevelUnset
	j := 0
	n := int(b.Entry[j])
	j++
	for k := 0; k < n; k++ {
		wireID := b.Entry[j+1]
		j += 2
		if !tree.HasWire(wireID) {
			continue
		}
		if level := tree.GetWireLevel(wireID); level > maxLevel {
			maxLevel = level
		}
	}
	maxLevel++
	tree.InsertWire(inst.WireOffset, maxLevel)
	return maxLevel
}

func (b *rawWireStateBlueprint[E]) Solve(s constraint.Solver[E], inst constraint.Instruction) error {
	value, _ := s.Read(b.Entry)
	s.SetValue(inst.WireOffset, value)
	return nil
}

func TestBlueprintStateDisablesAliasCompaction(t *testing.T) {
	for _, tc := range builderCases {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compile(t, tc, &blueprintStateAfterAliasCircuit{})
			if got := ccs.GetNbInternalVariables(); got < 2 {
				t.Fatalf("expected blueprint state to disable wire compaction, got %d internal wires", got)
			}
			validWitness, err := frontend.NewWitness(&blueprintStateAfterAliasCircuit{A: 2, B: 3, C: 1, D: 6, E: 5, F: 7}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid blueprint-state witness should solve after fallback alias constraints: %v", err)
			}
			invalidWitness, err := frontend.NewWitness(&blueprintStateAfterAliasCircuit{A: 2, B: 3, C: 1, D: 7, E: 5, F: 7}, tc.field)
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid aliased multiplication should still fail when blueprint state disables compaction")
			}
		})
	}
}

type builderCase struct {
	name       string
	field      *big.Int
	compile    func(testing.TB, frontend.Circuit) compiledSystem
	compileErr func(frontend.Circuit) error
}

var builderCases = []builderCase{
	{
		name:  "r1cs-u64",
		field: ecc.BN254.ScalarField(),
		compile: func(t testing.TB, circuit frontend.Circuit) compiledSystem {
			t.Helper()
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder[constraint.U64], circuit)
			if err != nil {
				t.Fatal(err)
			}
			return ccs
		},
		compileErr: func(circuit frontend.Circuit) error {
			_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder[constraint.U64], circuit)
			return err
		},
	},
	{
		name:  "scs-u64",
		field: ecc.BN254.ScalarField(),
		compile: func(t testing.TB, circuit frontend.Circuit) compiledSystem {
			t.Helper()
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder[constraint.U64], circuit)
			if err != nil {
				t.Fatal(err)
			}
			return ccs
		},
		compileErr: func(circuit frontend.Circuit) error {
			_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder[constraint.U64], circuit)
			return err
		},
	},
	{
		name:  "r1cs-u32",
		field: tinyfield.Modulus(),
		compile: func(t testing.TB, circuit frontend.Circuit) compiledSystem {
			t.Helper()
			ccs, err := frontend.CompileU32(tinyfield.Modulus(), r1cs.NewBuilder[constraint.U32], circuit)
			if err != nil {
				t.Fatal(err)
			}
			return ccs
		},
		compileErr: func(circuit frontend.Circuit) error {
			_, err := frontend.CompileU32(tinyfield.Modulus(), r1cs.NewBuilder[constraint.U32], circuit)
			return err
		},
	},
	{
		name:  "scs-u32",
		field: tinyfield.Modulus(),
		compile: func(t testing.TB, circuit frontend.Circuit) compiledSystem {
			t.Helper()
			ccs, err := frontend.CompileU32(tinyfield.Modulus(), scs.NewBuilder[constraint.U32], circuit)
			if err != nil {
				t.Fatal(err)
			}
			return ccs
		},
		compileErr: func(circuit frontend.Circuit) error {
			_, err := frontend.CompileU32(tinyfield.Modulus(), scs.NewBuilder[constraint.U32], circuit)
			return err
		},
	},
}

type compiledSystem interface {
	GetNbConstraints() int
	GetNbInternalVariables() int
	IsSolved(witness.Witness, ...solver.Option) error
}

func compile(t testing.TB, tc builderCase, circuit frontend.Circuit) compiledSystem {
	t.Helper()
	return tc.compile(t, circuit)
}

func internalEqualityAssignment(invalid bool) *internalEqualityCircuit {
	assignment := &internalEqualityCircuit{WithEqualities: true}
	for i := 0; i < nbEqualities; i++ {
		assignment.A[i] = 2
		assignment.B[i] = 3
		assignment.C[i] = 1
		assignment.D[i] = 6
	}
	if invalid {
		assignment.D[0] = 7
	}
	return assignment
}
