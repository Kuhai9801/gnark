package issue555

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
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
			base := compile(t, tc.builder, &internalEqualityCircuit{})
			withEqualities := compile(t, tc.builder, &internalEqualityCircuit{WithEqualities: true})

			baseConstraints := base.GetNbConstraints()
			withConstraints := withEqualities.GetNbConstraints()
			if baseConstraints != 32 {
				t.Fatalf("expected base circuit to have 32 constraints, got %d", baseConstraints)
			}
			if withConstraints != baseConstraints {
				t.Fatalf("expected internal equalities to be canonicalized, got base=%d withEqualities=%d", baseConstraints, withConstraints)
			}

			validWitness, err := frontend.NewWitness(internalEqualityAssignment(false), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := withEqualities.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve rewritten constraints: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(internalEqualityAssignment(true), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := withEqualities.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail after rewriting stale pre-merge constraints")
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
			ccs := compile(t, tc.builder, &secretEqualityCircuit{})
			if got := ccs.GetNbConstraints(); got != 1 {
				t.Fatalf("expected witness equality to emit one constraint, got %d", got)
			}

			validWitness, err := frontend.NewWitness(&secretEqualityCircuit{A: 5, B: 5}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve witness equality: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(&secretEqualityCircuit{A: 5, B: 6}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail because witness equality remains constrained")
			}
		})
	}
}

var builderCases = []struct {
	name    string
	builder frontend.NewBuilder
}{
	{name: "r1cs", builder: r1cs.NewBuilder[constraint.U64]},
	{name: "scs", builder: scs.NewBuilder[constraint.U64]},
}

func compile(t testing.TB, builder frontend.NewBuilder, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	return ccs
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
