package purbs

/* Code credit to Matthew Underwood, simplified by LB */

import (
	"fmt"
)

// RangeReservationLayout is used to represent a []byte array with (potentially overlapping) range=region reservations
// Expose "Reset()", "Reserve(range)", and "ScanFree"
type RegionReservationStruct struct {
	regions []*Region // important, those ranges are *always* sorted by startPos
}

// NewSkipLayout creates a new RangeReservationLayout
func NewRegionReservationStruct() *RegionReservationStruct {
	layout := new(RegionReservationStruct)
	layout.Reset()
	return layout
}

// Reset marks all regions as free
func (r *RegionReservationStruct) Reset() {
	r.regions = make([]*Region, 0)
}

// Adds a region, then performs insertion sort on the regions
func (r *RegionReservationStruct) addThenSort(startPos int, endPos int, label string) {
	newRegion := &Region{
		startPos: startPos,
		endPos: endPos,
		label: label,
	}
	r.regions = append(r.regions, newRegion)
	insertionSort(r.regions)
}

// Attempt to reserve a specific extent in the layout.
// If requireFree is true, either reserve it exclusively or fail without modification.
// If requireFree is false, reserve region even if some or all of it already reserved.
// Returns true if requested region was reserved exclusively, false if not.
func (r *RegionReservationStruct) Reserve(startPos int, endPos int, requireFree bool, label string) bool {

	// easiest case: if we don't care about the region being free, just add the region
	if !requireFree {
		r.addThenSort(startPos, endPos, label)
		return true
	}

	// harder case, we need to check whether the interval is free
	// dumb first step: coalesce all, then check
	coalescedRegions := onePassCoalesceRegions(r.regions)

	collision := false
	for _, region := range coalescedRegions {
		if endPos < region.startPos || startPos > region.endPos {
			// does not collide
		} else {
			fmt.Println("yes")
			collision = true
		}
	}

	if collision {
		// we couldn't reserve
		return false
	}

	r.addThenSort(startPos, endPos, label)
	return true
}

// Call the supplied function on every free region in the layout,
// up to a given maximum byte offset.
func (r *RegionReservationStruct) ScanFreeRegions(f func(int, int), maxByteOffset int) {

	if len(r.regions) == 0 {
		f(0, maxByteOffset)
		return
	}

	// coalesce all regions into ranges
	coalescedRegions := make([]*Region, 0)

	for _, region := range r.regions {
		hasCoalesced := false

		for i := range coalescedRegions {
			if region.DoesOverlapWith(coalescedRegions[i]) {
				// replace the region already in coalescedRegions with the new merged range
				coalescedRegions[i] = region.ComputeOverlap(coalescedRegions[i])
				hasCoalesced = true
			}
		}

		// we did not coalesce, just add
		if !hasCoalesced {
			coalescedRegions = append(coalescedRegions, region)
		} else {
			// we did coalesce, *but* we might have missed more coalescing (cascade), redo 1 pass
			coalescedRegions = onePassCoalesceRegions(coalescedRegions)
		}
	}

	// we have a coalesced region, just loop through and call the appropriate function
	currentOffset := 0
	for _, region := range coalescedRegions {

		if region.startPos > currentOffset {
			// we scan the free region between 0 and this range
			f(currentOffset, region.startPos)
		}

		currentOffset = region.endPos
	}

	// do not forget the region between the last range (if any) and the maxByteOffset (free by definition)
	if currentOffset < maxByteOffset {
		f(currentOffset, maxByteOffset)
	}
}

// tuple (startPos, endPos, label)
type Region struct {
	startPos   int
	endPos     int
	label      string
}

func (r *Region) ToString() string {
	s := ""
	s += fmt.Sprintf("%v:%v \"%v\"", r.startPos, r.endPos, r.label)
	return s
}

// returns true iff offset \in [startPos, endPos]
func (r *Region) Contains(offset int) bool {
	if offset < r.startPos || r.endPos < offset {
		return false
	}
	return true
}

// returns true iff the two regions overlap
func (r *Region) DoesOverlapWith(otherRegion *Region) bool {
	if r.Contains(otherRegion.startPos) || r.Contains(otherRegion.endPos) {
		return true
	}
	return false
}

// returns true iff the two regions overlap
func (r *Region) ComputeOverlap(otherRegion *Region) *Region {
	if !r.DoesOverlapWith(otherRegion) {
		panic("overlap can only be called on overlapping regions")
	}

	newRegion := new(Region)
	newRegion.startPos = r.startPos
	if otherRegion.startPos < r.startPos {
		newRegion.startPos = otherRegion.startPos
	}
	newRegion.endPos = r.endPos
	if otherRegion.endPos > r.endPos {
		newRegion.endPos = otherRegion.endPos
	}
	newRegion.label = fmt.Sprintf("[%v||%v]", r.label, otherRegion.label)
	return newRegion
}

func onePassCoalesceRegions(regions []*Region) []*Region {
	outputRegions := make([]*Region, 0)

	for _, region := range regions {
		// cornercase, the first block never coalesces
		if len(outputRegions) == 0 {
			outputRegions = append(outputRegions, region)
			continue
		}

		// if this region overlap with the previously registered region, replace it with the combination
		lastElem := len(outputRegions) - 1
		if region.DoesOverlapWith(outputRegions[lastElem]) {
			// replace the region already in coalescedRegions with the new merged range
			outputRegions[lastElem] = region.ComputeOverlap(outputRegions[lastElem])
		} else {
			// otherwise, we cannot coalesce, just add
			outputRegions = append(outputRegions, region)
		}
	}

	return outputRegions
}

func insertionSort(items []*Region) {
	var n = len(items)
	for i := 1; i < n; i++ {
		j := i
		for j > 0 {
			if items[j-1].startPos > items[j].startPos {
				items[j-1], items[j] = items[j], items[j-1]
			}
			j = j - 1
		}
	}
}