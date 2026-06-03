// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package wirealias

// Set tracks plain wire aliases for builder-owned internal wires.
type Set struct {
	parent       []int
	size         []int
	noAlias      []bool
	hasConstant  []bool
	constant     []uint32
	aliased      bool
	invalidated  bool
	constAliases bool
}

func (s *Set) ensure(vid int) {
	if vid < len(s.parent) {
		return
	}
	oldLen := len(s.parent)
	newLen := vid + 1
	s.parent = append(s.parent, make([]int, newLen-oldLen)...)
	s.size = append(s.size, make([]int, newLen-oldLen)...)
	s.noAlias = append(s.noAlias, make([]bool, newLen-oldLen)...)
	s.hasConstant = append(s.hasConstant, make([]bool, newLen-oldLen)...)
	s.constant = append(s.constant, make([]uint32, newLen-oldLen)...)
	for i := oldLen; i < newLen; i++ {
		s.parent[i] = i
		s.size[i] = 1
	}
}

func (s *Set) find(vid int) int {
	s.ensure(vid)
	root := vid
	for s.parent[root] != root {
		root = s.parent[root]
	}
	for s.parent[vid] != vid {
		parent := s.parent[vid]
		s.parent[vid] = root
		vid = parent
	}
	return root
}

// MarkInternal keeps builder call sites explicit. The builders decide which
// wires are internal before calling alias operations.
func (s *Set) MarkInternal(vid int) {
}

// MarkNoAlias excludes the wire's current alias class from equality
// elimination. This is used for public inputs, user witness slots, hints,
// commitments, and custom/backend escape hatches.
func (s *Set) MarkNoAlias(vid int) {
	root := s.find(vid)
	if !s.noAlias[vid] && vid != root && s.size[root] > 1 {
		s.invalidated = true
	}
	s.noAlias[vid] = true
	s.noAlias[root] = true
}

// CanAlias reports whether x and y are still safe to merge.
func (s *Set) CanAlias(x, y int) bool {
	rx, ry := s.find(x), s.find(y)
	return !s.hasConstant[rx] && !s.hasConstant[ry] &&
		!s.noAlias[x] && !s.noAlias[y] &&
		!s.noAlias[rx] && !s.noAlias[ry]
}

// Union records x == y and prefers the lower wire ID as representative. The
// method returns false when the equality is unsafe to optimize and must remain
// an explicit constraint.
func (s *Set) Union(x, y int) bool {
	if !s.CanAlias(x, y) {
		return false
	}
	rx, ry := s.find(x), s.find(y)
	if rx == ry {
		return true
	}
	if ry < rx {
		rx, ry = ry, rx
	}
	s.parent[ry] = rx
	s.size[rx] += s.size[ry]
	s.noAlias[rx] = s.noAlias[rx] || s.noAlias[ry]
	s.aliased = true
	return true
}

// AliasToWire records internal == external and prefers the external wire as
// representative. This is used for input aliases.
func (s *Set) AliasToWire(internal, wire int) bool {
	root := s.find(internal)
	if s.noAlias[internal] || s.noAlias[root] || s.hasConstant[root] {
		return false
	}
	wireRoot := s.find(wire)
	s.parent[root] = wireRoot
	s.size[wireRoot] += s.size[root]
	s.aliased = true
	return true
}

// AliasToConstant records internal == constant.
func (s *Set) AliasToConstant(internal int, coeffID uint32) bool {
	root := s.find(internal)
	if s.noAlias[internal] || s.noAlias[root] || s.hasConstant[root] {
		return false
	}
	s.hasConstant[root] = true
	s.constant[root] = coeffID
	s.aliased = true
	s.constAliases = true
	return true
}

// Rep returns the current representative for vid.
func (s *Set) Rep(vid int) int {
	root := s.find(vid)
	if s.hasConstant[root] || s.noAlias[vid] {
		return vid
	}
	return root
}

// Constant returns the constant coefficient ID for vid's alias class.
func (s *Set) Constant(vid int) (uint32, bool) {
	root := s.find(vid)
	if !s.hasConstant[root] {
		return 0, false
	}
	return s.constant[root], true
}

// HasAliases reports whether at least one non-trivial union was recorded.
func (s *Set) HasAliases() bool {
	return s.aliased
}

// HasConstantAliases reports whether any alias class resolves to a constant.
func (s *Set) HasConstantAliases() bool {
	return s.constAliases
}

// Invalidated reports whether an alias class escaped after it had already been
// merged. The builder cannot safely undo earlier representative rewrites.
func (s *Set) Invalidated() bool {
	return s.invalidated
}

// Eliminated returns internal wires removed by aliases.
func (s *Set) Eliminated() []int {
	if !s.aliased {
		return nil
	}
	res := make([]int, 0)
	for vid := range s.parent {
		root := s.find(vid)
		if s.hasConstant[root] || (root != vid && !s.noAlias[vid]) {
			res = append(res, vid)
		}
	}
	return res
}
