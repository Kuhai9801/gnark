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

type builderCase struct {
	name    string
	builder frontend.NewBuilder
}

func builderCases() []builderCase {
	return []builderCase{
		{name: "r1cs", builder: r1cs.NewBuilder[constraint.U64]},
		{name: "scs", builder: scs.NewBuilder[constraint.U64]},
	}
}

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

func TestInternalEqualityConstraintCounts(t *testing.T) {
	for _, tc := range builderCases() {
		t.Run(tc.name, func(t *testing.T) {
			base := compileCircuit(t, tc.builder, &internalEqualityCircuit{})
			withEqualities := compileCircuit(t, tc.builder, &internalEqualityCircuit{WithEqualities: true})

			baseConstraints := base.GetNbConstraints()
			withConstraints := withEqualities.GetNbConstraints()
			t.Logf("base=%d withEqualities=%d delta=%d", baseConstraints, withConstraints, withConstraints-baseConstraints)

			if baseConstraints != 32 {
				t.Fatalf("expected base circuit to have 32 constraints, got %d", baseConstraints)
			}
			if withConstraints != baseConstraints {
				t.Fatalf("expected internal equalities to be canonicalized, got base=%d withEqualities=%d", baseConstraints, withConstraints)
			}
		})
	}
}

func TestInternalEqualityStaleConstraintsAreRewritten(t *testing.T) {
	for _, tc := range builderCases() {
		t.Run(tc.name, func(t *testing.T) {
			ccs := compileCircuit(t, tc.builder, &internalEqualityCircuit{WithEqualities: true})

			validWitness, err := frontend.NewWitness(internalEqualityAssignment(false), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(validWitness); err != nil {
				t.Fatalf("valid witness should solve rewritten constraints: %v", err)
			}

			invalidWitness, err := frontend.NewWitness(internalEqualityAssignment(true), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(invalidWitness); err == nil {
				t.Fatal("invalid witness should fail after rewriting stale pre-merge constraints")
			}
		})
	}
}

type publicEqualityCircuit struct {
	P frontend.Variable `gnark:",public"`
	Q frontend.Variable `gnark:",public"`
}

func (c *publicEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.P, c.Q)
	return nil
}

type secretEqualityCircuit struct {
	A, B frontend.Variable
}

func (c *secretEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.A, c.B)
	return nil
}

type publicSecretEqualityCircuit struct {
	P frontend.Variable `gnark:",public"`
	S frontend.Variable
}

func (c *publicSecretEqualityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.P, c.S)
	return nil
}

func TestUnsafeEqualitiesRemainConstrained(t *testing.T) {
	tests := []struct {
		name    string
		circuit frontend.Circuit
		valid   frontend.Circuit
		invalid frontend.Circuit
	}{
		{
			name:    "public-public",
			circuit: &publicEqualityCircuit{},
			valid:   &publicEqualityCircuit{P: 3, Q: 3},
			invalid: &publicEqualityCircuit{P: 3, Q: 4},
		},
		{
			name:    "secret-secret",
			circuit: &secretEqualityCircuit{},
			valid:   &secretEqualityCircuit{A: 5, B: 5},
			invalid: &secretEqualityCircuit{A: 5, B: 6},
		},
		{
			name:    "public-secret",
			circuit: &publicSecretEqualityCircuit{},
			valid:   &publicSecretEqualityCircuit{P: 7, S: 7},
			invalid: &publicSecretEqualityCircuit{P: 7, S: 8},
		},
	}

	for _, tc := range builderCases() {
		for _, test := range tests {
			t.Run(tc.name+"/"+test.name, func(t *testing.T) {
				ccs := compileCircuit(t, tc.builder, test.circuit)
				if got := ccs.GetNbConstraints(); got != 1 {
					t.Fatalf("expected unsafe equality to emit one constraint, got %d", got)
				}

				validWitness, err := frontend.NewWitness(test.valid, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := ccs.IsSolved(validWitness); err != nil {
					t.Fatalf("valid witness should solve unsafe equality: %v", err)
				}

				invalidWitness, err := frontend.NewWitness(test.invalid, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := ccs.IsSolved(invalidWitness); err == nil {
					t.Fatal("invalid witness should fail because unsafe equality remains constrained")
				}
			})
		}
	}
}

func BenchmarkInternalEqualityCompile(b *testing.B) {
	for _, tc := range builderCases() {
		for _, withEqualities := range []bool{false, true} {
			name := tc.name + "/base"
			if withEqualities {
				name = tc.name + "/withEqualities"
			}
			b.Run(name, func(b *testing.B) {
				var constraints int
				for i := 0; i < b.N; i++ {
					ccs, err := frontend.Compile(
						ecc.BN254.ScalarField(),
						tc.builder,
						&internalEqualityCircuit{WithEqualities: withEqualities},
					)
					if err != nil {
						b.Fatal(err)
					}
					constraints = ccs.GetNbConstraints()
				}
				b.ReportMetric(float64(constraints), "constraints")
			})
		}
	}
}

func compileCircuit(t testing.TB, builder frontend.NewBuilder, circuit frontend.Circuit) constraint.ConstraintSystem {
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
