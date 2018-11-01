package purbs

/* Code credit to Matthew Underwood*/

import (
	"encoding/binary"
	"github.com/dedis/kyber/util/random"
)

// Pick a uint32 uniformly at random
func randUint32() uint32 {
	b := make([]byte, 4)
	random.Bytes(b, random.New())
	return binary.LittleEndian.Uint32(b)
}

// Pick a random height for a new skip-list node from a suitable distribution.
func skipHeight() int {
	height := 1
	for v := randUint32() | (1 << 31); v&1 == 0; v >>= 1 {
		height++
	}
	return height
}

// low - start, high - end, s
// uc - next
type skipNode struct {
	low, high int
	suc       []*skipNode
	name      string
}

// Skip-list reservation structure.
// XXX currently we never coalesce reserved regions,
// and operation would probably be much more efficient if we did.
type SkipLayout struct {
	head []*skipNode
}

// Marks all regions as free
func (sl *SkipLayout) Reset() {
	sl.head = make([]*skipNode, 1) // minimum stack height
}

// Create a new skip-list iterator.
// An iterator is a stack of pointers to next pointers, one per level.
func (sl *SkipLayout) iter() []**skipNode {
	pos := make([]**skipNode, len(sl.head))
	for i := range pos {
		pos[i] = &sl.head[i]
	}
	return pos
}

// Advance a position vector past a given node,
// which must be pointed to by one of the current position pointers.
func (sl *SkipLayout) skip(pos []**skipNode, past *skipNode) {
	for i := range past.suc {
		pos[i] = &past.suc[i]
	}
}

// Find the position past all nodes strictly before byte offset ofs.
func (sl *SkipLayout) find(ofs int) []**skipNode {
	pos := sl.iter()
	for i := len(pos) - 1; i >= 0; i-- {
		for n := *pos[i]; n != nil && n.high <= ofs; n = *pos[i] {
			// Advance past n at all levels up through i
			sl.skip(pos, n)
		}
	}
	return pos
}

// Insert a new node at a given iterator position, and skip past it.
// May extend the iterator slice, so returns a new position slice.
func (sl *SkipLayout) insert(pos []**skipNode, lo, hi int,
	name string) []**skipNode {

	nsuc := make([]*skipNode, skipHeight())
	n := skipNode{lo, hi, nsuc, name}

	// Insert the new node at all appropriate levels
	for i := range nsuc {
		if i == len(pos) {
			// base node's stack not high enough, extend it
			sl.head = append(sl.head, nil)
			pos = append(pos, &sl.head[i])
		}
		nsuc[i] = *pos[i]
		*pos[i] = &n
		pos[i] = &nsuc[i]
	}
	return pos
}

// Attempt to reserve a specific extent in the layout.
// If excl is true, either reserve it exclusively or fail without modification.
// If excl is false, reserve region even if some or all of it already reserved.
// Returns true if requested region was reserved exclusively, false if not.
func (sl *SkipLayout) Reserve(lo, hi int, excl bool, name string) bool {

	// Find the position past all nodes strictly before our interest area
	pos := sl.find(lo)

	// Can we get an exclusive reservation?
	suc := *pos[0]
	gotExcl := true
	if suc != nil && suc.low < hi { // suc overlaps what we want?
		if excl {
			return false // excl required but can't get
		}
		gotExcl = false
	}

	// Reserve any parts of this extent not already reserved.
	for lo < hi {
		suc = *pos[0]
		if suc != nil && suc.low <= lo {
			// suc occupies first part of our region, so skip it
			lo = suc.high
			sl.skip(pos, suc)
			continue
		}

		// How big of a reservation can we insert here?
		inshi := hi
		if suc != nil && suc.low < inshi {
			inshi = suc.low // end at start of next existing region
		}
		if lo >= inshi {
			panic("trying to insert empty reservation")
		}
		//log.Printf("Skip inserting [%d-%d]\n", lo, hi)

		// Insert a new reservation here, then skip past it.
		pos = sl.insert(pos, lo, inshi, name)
		lo = inshi
	}

	return gotExcl
}

// Find and reserve the first available l-byte region in the layout.
func (sl *SkipLayout) alloc(l int, name string) int {

	pos := sl.iter()
	ofs := 0
	for { // Find a position to insert
		suc := *pos[0]
		if suc == nil {
			break // no more reservations; definitely room here!
		}
		avail := suc.low - ofs
		if avail >= l {
			break // there's enough room here
		}
		sl.skip(pos, suc)
		ofs = suc.high
	}

	// Insert new region here
	sl.insert(pos, ofs, ofs+l, name)
	return ofs
}

// Call the supplied function on every free region in the layout,
// up to a given maximum byte offset.
func (sl *SkipLayout) scanFree(f func(int, int), max int) {

	pos := sl.iter()
	ofs := 0
	for {
		suc := *pos[0]
		if suc == nil {
			break // no more reservations
		}
		if suc.low > ofs {
			//log.Printf("The zone to random [%d-%d]\n", ofs, suc.low)
			f(ofs, suc.low)
		}
		sl.skip(pos, suc)
		ofs = suc.high
	}
	if ofs < max {
		f(ofs, max)
	}
}

func (sl *SkipLayout) dump() {

	pos := make([]**skipNode, len(sl.head))
	//fmt.Printf("Skip-list levels: %d\n", len(pos))
	for i := range pos {
		pos[i] = &sl.head[i]
		//fmt.Printf(" H%d: %p\n", i, *pos[i])
	}
	for n := *pos[0]; n != nil; n = *pos[0] {
		for j := range n.suc { // skip-list invariant check
			//fmt.Printf(" S%d: %p\n", j, n.suc[j])
			if *pos[j] != n {
				panic("bad suc pointer")
			}
			pos[j] = &n.suc[j]
		}
	}
	for i := range pos {
		n := *pos[i]
		if n != nil {
			panic("orphaned skip-node: " + n.name)
		}
	}
}
