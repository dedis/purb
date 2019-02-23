package purbs

/* Code credit to Matthew Underwood, simplified by LB */

import (
	"fmt"
)

// RangeReservationLayout is used to represent a []byte array with (potentially overlapping) range=byteRangeForAllowedPositionIndex reservations
// Expose "Reset()", "Reserve(range)", and "ScanFree"
type RegionReservationStruct struct {
	regions          []*Region // important, those ranges are *always* sorted by startPos
	coalescedRegions []*Region // same as "regions" but coalesced, e.g., [10-150],[100-1000] becomes [10-1000]
}

// NewSkipLayout creates a new RangeReservationLayout
func NewRegionReservationStruct() *RegionReservationStruct {
	layout := new(RegionReservationStruct)
	layout.Reset()
	return layout
}

// Deep-clone structure
func (r *RegionReservationStruct) Clone() *RegionReservationStruct {

	r2 := NewRegionReservationStruct()

	r2.regions = make([]*Region, 0)
	for _, region := range r.regions {
		r2.regions = append(r2.regions, &Region{
			startPos: region.startPos,
			endPos:   region.endPos,
			label:    region.label,
		})
	}

	r2.coalescedRegions = make([]*Region, 0)
	for _, region := range r.coalescedRegions {
		r2.coalescedRegions = append(r2.coalescedRegions, &Region{
			startPos: region.startPos,
			endPos:   region.endPos,
			label:    region.label,
		})
	}

	return r2
}

// Reset marks all regions as free
func (r *RegionReservationStruct) Reset() {
	r.regions = make([]*Region, 0)
	r.coalescedRegions = make([]*Region, 0)
}

// Adds a byteRangeForAllowedPositionIndex, then performs insertion sort on the regions
func (r *RegionReservationStruct) addThenSort(startPos int, endPos int, label string) {
	newRegion := &Region{
		startPos: startPos,
		endPos:   endPos,
		label:    label,
	}
	r.regions = append(r.regions, newRegion)
	insertionSort(r.regions)
	r.coalescedRegions = coalesceRegions(r.regions)
}

// Returns true iff the requested byteRangeForAllowedPositionIndex is free
func (r *RegionReservationStruct) IsFree(startPos int, endPos int) bool {

	// if the layout is empty, everything is free!
	if len(r.regions) == 0 {
		return true
	}

	// check if there is a conflict with a coalesced byteRangeForAllowedPositionIndex
	for _, region := range r.coalescedRegions {
		if startPos >= region.endPos || endPos <= region.startPos {
			// does not collide
		} else {
			return false
		}
	}
	return true
}

// Attempt to reserve a specific extent in the layout.
// Region work as [startPos, endPos[
// If requireFree is true, attempt to reserve it exclusively (return true) or fails (return false)
// If requireFree is false, reserve byteRangeForAllowedPositionIndex even if some or all of it already reserved. (always returns true)
// Returns true if requested byteRangeForAllowedPositionIndex was reserved, false if not.
func (r *RegionReservationStruct) Reserve(startPos int, endPos int, requireFree bool, label string) bool {

	// easiest case: if we don't care about the byteRangeForAllowedPositionIndex being free, just add the byteRangeForAllowedPositionIndex
	if !requireFree {
		r.addThenSort(startPos, endPos, label)
		return true
	}

	// other case, we need to check whether the interval is free
	if !r.IsFree(startPos, endPos) {
		// we couldn't reserve
		return false
	}

	r.addThenSort(startPos, endPos, label)
	return true
}

// Call the supplied function on every free byteRangeForAllowedPositionIndex in the layout,
// up to a given maximum byte offset.
func (r *RegionReservationStruct) ScanFreeRegions(f func(int, int), maxByteOffset int) {

	if len(r.regions) == 0 {
		f(0, maxByteOffset)
		return
	}

	// coalesce all regions into ranges
	coalescedRegions := r.coalescedRegions

	// we have a coalesced byteRangeForAllowedPositionIndex, just loop through and call the appropriate function
	currentOffset := 0
	for _, region := range coalescedRegions {

		if region.startPos > currentOffset {
			// we scan the free byteRangeForAllowedPositionIndex between 0 and this range
			f(currentOffset, region.startPos)
		}

		currentOffset = region.endPos
	}

	// do not forget the byteRangeForAllowedPositionIndex between the last range (if any) and the maxByteOffset (free by definition)
	if currentOffset < maxByteOffset {
		f(currentOffset, maxByteOffset)
	}
}

// ToString // thank you golang for forcing me to comment on "ToString()"
func (r *RegionReservationStruct) ToString() string {
	s := ""
	for k, region := range r.regions {
		s += fmt.Sprintf("%v: %v\n", k, region.ToString())
	}
	return s
}

// tuple (startPos, endPos, label)
type Region struct {
	startPos int
	endPos   int
	label    string
}

// ToString // thank you golang for forcing me to comment on "ToString()"
func (r *Region) ToString() string {
	s := ""
	s += fmt.Sprintf("%v:%v \"%v\"", r.startPos, r.endPos, r.label)
	return s
}

// returns true iff the two regions overlap
func (r *Region) DoesOverlapWith(otherRegion *Region) bool {

	// r fully before otherRegion
	if r.endPos <= otherRegion.startPos {
		return false
	}
	// otherregion fully before r
	if otherRegion.endPos <= r.startPos {
		return false
	}
	return true
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

func coalesceRegions(regions []*Region) []*Region {
	coalescedRegions := make([]*Region, 0)

	for _, region := range regions {
		hasCoalesced := false

		for i := range coalescedRegions {
			if region.DoesOverlapWith(coalescedRegions[i]) {
				// replace the byteRangeForAllowedPositionIndex already in coalescedRegions with the new merged range
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
	return coalescedRegions
}

func onePassCoalesceRegions(regions []*Region) []*Region {

	outputRegions := make([]*Region, 0)

	for _, region := range regions {
		// cornercase, the first block never coalesces
		if len(outputRegions) == 0 {
			outputRegions = append(outputRegions, region)
			continue
		}

		// if this byteRangeForAllowedPositionIndex overlap with the previously registered byteRangeForAllowedPositionIndex, replace it with the combination
		lastElem := len(outputRegions) - 1
		if region.DoesOverlapWith(outputRegions[lastElem]) {
			// replace the byteRangeForAllowedPositionIndex already in coalescedRegions with the new merged range
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
