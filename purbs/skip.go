package purbs

/* Code credit to Matthew Underwood, simplified by LB */

import (
	"fmt"
	"github.com/dedis/onet/log"
)

// RangeReservationLayout is used to represent a []byte array with (potentially overlapping) range reservations
// Expose "Reset()" and "Reserve(range)"
// Think of Ranges as column-wise (along X axis); this struct has several *rows* of Ranges
type RangeReservationLayout struct {
	rows []*Range
}

// NewSkipLayout creates a new RangeReservationLayout
func NewRangeReservationLayout() *RangeReservationLayout {
	layout := new(RangeReservationLayout)
	layout.Reset()
	return layout
}

// Reset marks all regions as free
func (r *RangeReservationLayout) Reset() {
	r.rows = make([]*Range, 1) //only one head, which is empty
}

// Attempt to reserve a specific extent in the layout.
// If excl is true, either reserve it exclusively or fail without modification.
// If excl is false, reserve region even if some or all of it already reserved.
// Returns true if requested region was reserved exclusively, false if not.
func (r *RangeReservationLayout) Reserve(startPos int, endPos int, requireFree bool, label string) bool {

	// Find the position past all nodes strictly before our interest area
	iterators := r.findAllRangesStrictlyBefore(startPos)

	// Can we get an exclusive reservation?
	firstRange := *iterators[0]
	dataOverwritten := true
	if firstRange != nil && firstRange.startPos < endPos { // successors overlaps what we want?
		if requireFree {
			return false // we require the region to be free, but it's not, abort
		}
		dataOverwritten = false // we didn't require the region to be free, gonna reserve, but indicate that we overwrote something
	}

	// Reserve any parts of this extent not already reserved.
	for startPos < endPos {
		firstRange = *iterators[0]
		if firstRange != nil && firstRange.startPos <= startPos {
			// successors occupies first part of our region, so advanceIteratorUntil it
			startPos = firstRange.endPos
			r.advanceIteratorUntil(iterators, firstRange)
			continue
		}

		// How big of a reservation can we insertBefore here?
		alternativeEndPos := endPos
		if firstRange != nil && firstRange.startPos < alternativeEndPos {
			alternativeEndPos = firstRange.startPos // end at start of next existing region
		}
		if startPos >= alternativeEndPos {
			panic("trying to insertBefore empty reservation")
		}
		log.Printf("Skip inserting [%d-%d]\n", startPos, endPos)

		// Insert a new reservation here, then advance past it.
		iterators = r.insertBefore(iterators, startPos, alternativeEndPos, label)
		startPos = alternativeEndPos
	}

	return dataOverwritten
}

// Call the supplied function on every free region in the layout,
// up to a given maximum byte offset.
func (r *RangeReservationLayout) ScanFreeRegions(f func(int, int), maxByteOffset int) {

	iterators := r.iterators()
	startOffset := 0
	for {
		currentRange := *iterators[0]
		if currentRange == nil {
			break
		}
		if currentRange.startPos > startOffset {
			// we scan the free region between 0 and this range
			f(startOffset, currentRange.startPos)
		}
		r.advanceIteratorUntil(iterators, currentRange)
		startOffset = currentRange.endPos
	}
	// do not forget the region between the last range (if any) and the maxByteOffset (free by definition)
	if startOffset < maxByteOffset {
		f(startOffset, maxByteOffset)
	}
}

// tuple (startPos, endPos, label) with potentially linked successors (this is the elem of a linked list)
type Range struct {
	startPos   int
	endPos     int
	label      string
	successors []*Range
}

func (r *Range) ToString() string {
	s := ""
	s += fmt.Sprintf("[%v:%v \"%v\", successors: %v]", r.startPos, r.endPos, r.label, len(r.successors))
	return s
}

// An iterators is a stack of pointers to next pointers, one per level.
func (r *RangeReservationLayout) iterators() []**Range {

	iterators := make([]**Range, len(r.rows))

	// copy the rows into the iterator
	for i := range iterators {
		iterators[i] = &r.rows[i]
	}
	return iterators
}

// Advance an iterator past a given node, which must be pointed to by one of the current iterator pointers.
func (r *RangeReservationLayout) advanceIteratorUntil(iterator []**Range, past *Range) {
	for i := range past.successors {
		iterator[i] = &past.successors[i]
	}
}

// Find all the ranges strictly before the byte offset.
func (r *RangeReservationLayout) findAllRangesStrictlyBefore(byteOffset int) []**Range {

	iterators := r.iterators()

	//for each iterator, starting from the deepest
	for row := len(iterators) - 1; row >= 0; row-- {

		// find all nodes in this list, iff the highPos of the node is <= of the considered byteOffset
		for {
			currentRange := *iterators[row]

			if currentRange == nil {
				break
			}
			if currentRange.endPos > byteOffset {
				break
			}

			r.advanceIteratorUntil(iterators, currentRange)
		}
	}
	return iterators
}

// Insert a new node at a given iterators position, and advance past it.
// May extend the iterators slice, so returns a new position slice.
func (r *RangeReservationLayout) insertBefore(iterators []**Range, startPos int, endPos int, label string) []**Range {

	successors := make([]*Range, 1)
	n := Range{startPos, endPos, label, successors}

	// Insert the new node at all appropriate levels
	for i := range successors {

		if i == len(iterators) {
			// base node's stack not high enough, extend it
			r.rows = append(r.rows, nil)
			iterators = append(iterators, &r.rows[i])
		}
		// copy the first Range into "successor"
		successors[i] = *iterators[i]

		// the previous Range (now copied into "successor") is this node being built
		*iterators[i] = &n

		// in the thing we return, we return this range
		iterators[i] = &successors[i]
	}
	return iterators
}

func (r *RangeReservationLayout) dump() {

	iterators := make([]**Range, len(r.rows))
	fmt.Printf("rows: %d\n", len(iterators))

	for i := range iterators {
		iterators[i] = &r.rows[i]
		if *iterators[i] != nil {
			fmt.Printf(" H%d: %v\n", i, (*iterators[i]).ToString())
		} else {
			fmt.Printf(" H%d: nil\n", i)
		}
	}

	currentRange := *iterators[0]
	for {
		if currentRange == nil {
			break
		}

		for j := range currentRange.successors {

			if currentRange.successors[j] != nil {
				fmt.Printf(" S%d: %v\n", j, currentRange.successors[j].ToString())
			} else {
				fmt.Printf(" S%d: nil\n", j)
			}

			if *iterators[j] != currentRange {
				panic("bad successors pointer")
			}
			iterators[j] = &currentRange.successors[j]
		}

		currentRange = *iterators[0]
	}
	for i := range iterators {
		n := *iterators[i]
		if n != nil {
			panic("orphaned advanceIteratorUntil-node: " + n.label)
		}
	}
}
