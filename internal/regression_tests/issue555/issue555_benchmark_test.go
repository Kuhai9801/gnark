package issue555

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
)

type aliasBenchmarkMode uint8

const (
	aliasBenchmarkNone aliasBenchmarkMode = iota
	aliasBenchmarkOneLate
	aliasBenchmarkManyEarly
	aliasBenchmarkManyLate
)

type aliasBenchmarkCircuit struct {
	Mode       aliasBenchmarkMode `gnark:"-"`
	A, B, C, D []frontend.Variable
}

func newAliasBenchmarkCircuit(n int, mode aliasBenchmarkMode) *aliasBenchmarkCircuit {
	return &aliasBenchmarkCircuit{
		Mode: mode,
		A:    make([]frontend.Variable, n),
		B:    make([]frontend.Variable, n),
		C:    make([]frontend.Variable, n),
		D:    make([]frontend.Variable, n),
	}
}

func (c *aliasBenchmarkCircuit) Define(api frontend.API) error {
	left := make([]frontend.Variable, len(c.A))
	right := make([]frontend.Variable, len(c.A))
	for i := range c.A {
		left[i] = api.Mul(c.A[i], c.B[i])
		right[i] = api.Mul(c.C[i], c.D[i])
		if c.Mode == aliasBenchmarkManyEarly {
			api.AssertIsEqual(left[i], right[i])
		}
	}

	switch c.Mode {
	case aliasBenchmarkOneLate:
		api.AssertIsEqual(left[0], right[len(right)-1])
	case aliasBenchmarkManyLate:
		for i := range left {
			api.AssertIsEqual(left[i], right[i])
		}
	}
	return nil
}

type mixedAliasBenchmarkCircuit struct {
	A, B, C, D []frontend.Variable
}

func newMixedAliasBenchmarkCircuit(n int) *mixedAliasBenchmarkCircuit {
	return &mixedAliasBenchmarkCircuit{
		A: make([]frontend.Variable, n),
		B: make([]frontend.Variable, n),
		C: make([]frontend.Variable, n),
		D: make([]frontend.Variable, n),
	}
}

func (c *mixedAliasBenchmarkCircuit) Define(api frontend.API) error {
	values := make([]frontend.Variable, len(c.A))
	for i := range c.A {
		x := api.Mul(c.A[i], c.B[i])
		h, err := api.Compiler().NewHint(aliasBenchmarkHint, 1, x)
		if err != nil {
			return err
		}
		api.AssertIsEqual(h[0], x)
		values[i] = api.Add(x, 1)
		if i%2 == 0 {
			left := api.Mul(c.A[i], c.C[i])
			right := api.Mul(c.B[i], c.D[i])
			api.AssertIsEqual(left, right)
		}
	}

	batchInverter := api.(interface {
		BatchInvert([]frontend.Variable) []frontend.Variable
	})
	inv := batchInverter.BatchInvert(values)
	for i := range inv {
		api.AssertIsEqual(api.Mul(inv[i], values[i]), 1)
	}

	compiler := api.Compiler()
	bID := compiler.AddBlueprint(aliasBenchmarkNoOpBlueprint{})
	compiler.AddInstruction(bID, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	return nil
}

func aliasBenchmarkHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

type aliasBenchmarkNoOpBlueprint struct{}

func (aliasBenchmarkNoOpBlueprint) CalldataSize() int {
	return 10
}

func (aliasBenchmarkNoOpBlueprint) NbConstraints() int {
	return 0
}

func (aliasBenchmarkNoOpBlueprint) NbOutputs(constraint.Instruction) int {
	return 0
}

func (aliasBenchmarkNoOpBlueprint) UpdateInstructionTree(constraint.Instruction, constraint.InstructionTree) constraint.Level {
	return 0
}

type aliasBenchmarkBuilderCase struct {
	name    string
	compile func(testing.TB, frontend.Circuit)
}

var aliasBenchmarkBuilderCases = []aliasBenchmarkBuilderCase{
	{
		name: "r1cs-u64",
		compile: func(t testing.TB, circuit frontend.Circuit) {
			t.Helper()
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder[constraint.U64], circuit); err != nil {
				t.Fatal(err)
			}
		},
	},
	{
		name: "scs-u64",
		compile: func(t testing.TB, circuit frontend.Circuit) {
			t.Helper()
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder[constraint.U64], circuit); err != nil {
				t.Fatal(err)
			}
		},
	},
	{
		name: "r1cs-u32",
		compile: func(t testing.TB, circuit frontend.Circuit) {
			t.Helper()
			if _, err := frontend.CompileU32(tinyfield.Modulus(), r1cs.NewBuilder[constraint.U32], circuit); err != nil {
				t.Fatal(err)
			}
		},
	},
	{
		name: "scs-u32",
		compile: func(t testing.TB, circuit frontend.Circuit) {
			t.Helper()
			if _, err := frontend.CompileU32(tinyfield.Modulus(), scs.NewBuilder[constraint.U32], circuit); err != nil {
				t.Fatal(err)
			}
		},
	},
}

func BenchmarkCompileWireAliases(b *testing.B) {
	const n = 256
	cases := []struct {
		name       string
		newCircuit func() frontend.Circuit
	}{
		{"no_aliases", func() frontend.Circuit { return newAliasBenchmarkCircuit(n, aliasBenchmarkNone) }},
		{"one_late_alias", func() frontend.Circuit { return newAliasBenchmarkCircuit(n, aliasBenchmarkOneLate) }},
		{"many_early_aliases", func() frontend.Circuit { return newAliasBenchmarkCircuit(n, aliasBenchmarkManyEarly) }},
		{"many_late_aliases", func() frontend.Circuit { return newAliasBenchmarkCircuit(n, aliasBenchmarkManyLate) }},
		{"mixed_escape_hatches", func() frontend.Circuit { return newMixedAliasBenchmarkCircuit(n) }},
	}

	for _, tc := range aliasBenchmarkBuilderCases {
		b.Run(tc.name, func(b *testing.B) {
			for _, bc := range cases {
				b.Run(bc.name, func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						tc.compile(b, bc.newCircuit())
					}
				})
			}
		})
	}
}
