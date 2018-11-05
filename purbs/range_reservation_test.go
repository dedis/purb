package purbs

import (
	"strconv"
	"testing"
)

func TestInsertionSort(t *testing.T) {
	input := []int{503, -319, 245, -537, -167, -804, 469, -457, 143, 184, 376, 825, 11, -309, -144, 152, -493, 684, 165, 29}
	output := []int{-804, -537, -493, -457, -319, -309, -167, -144, 11, 29, 143, 152, 165, 184, 245, 376, 469, 503, 684, 825}

	regionsInputs := make([]*Region, 0)

	for _, i := range input {
		regionsInputs = append(regionsInputs, &Region{
			startPos: i,
		})
	}

	insertionSort(regionsInputs)

	for k, v := range output {
		if output[k] != regionsInputs[k].startPos {
			t.Error("Position", k, "should have value", v, "has value", regionsInputs[k])
		}
	}
}

func TestRangeReservation(t *testing.T) {

	layout := NewRegionReservationStruct()

	// at first, all should be empty
	endPos := 1000
	scanner := func(start, end int) {
		if start != 0 {
			t.Error("Scanner should start at 0")
		}
		if end != endPos {
			t.Error("Scanner should end at 1000")
		}
	}
	layout.ScanFreeRegions(scanner, endPos)

	// scanning should not touch anything, retest
	layout.ScanFreeRegions(scanner, endPos)

	// reserving should work
	success := layout.Reserve(10, 100, true, "block10-100")
	if !success {
		t.Error("Reserve should work")
	}

	// scanner should give two regions
	regions := make([]string, 0)
	scanner = func(start, end int) {
		regions = append(regions, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	layout.ScanFreeRegions(scanner, endPos)
	if regions[0] != "0:10" {
		t.Error("First free byteRangeForAllowedPositionIndex should be 0:10")
	}
	if regions[1] != "100:1000" {
		t.Error("Second free byteRangeForAllowedPositionIndex should be 100:1000")
	}

	// overlapping reservation should fail is requireFree is asked
	success = layout.Reserve(50, 200, true, "block50-200")
	if success {
		t.Error("Reserve should not work")
	}

	// non-overlapping reservation should succeed
	success = layout.Reserve(150, 200, true, "block150-200")
	if !success {
		t.Error("Reserve should work")
	}

	// scanner should give three regions
	regions = make([]string, 0)
	scanner = func(start, end int) {
		regions = append(regions, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	layout.ScanFreeRegions(scanner, endPos)
	if regions[0] != "0:10" {
		t.Error("First free byteRangeForAllowedPositionIndex should be 0:10, was", regions[0])
	}
	if regions[1] != "100:150" {
		t.Error("Second free byteRangeForAllowedPositionIndex should be 100:150, was", regions[1])
	}
	if regions[2] != "200:1000" {
		t.Error("Third free byteRangeForAllowedPositionIndex should be 200:1000, was", regions[2])
	}

	// Coalescing should work
	success = layout.Reserve(100, 150, true, "block100-150")
	if !success {
		t.Error("Reserve should work")
	}

	// scanner should give two regions
	regions = make([]string, 0)
	scanner = func(start, end int) {
		regions = append(regions, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	layout.ScanFreeRegions(scanner, endPos)
	if regions[0] != "0:10" {
		t.Error("First free byteRangeForAllowedPositionIndex should be 0:10, was", regions[0])
	}
	if regions[1] != "200:1000" {
		t.Error("Second free byteRangeForAllowedPositionIndex should be 200:1000, was", regions[1])
	}

	// Coalescing should work
	success = layout.Reserve(3, 203, false, "block2-3")
	if !success {
		t.Error("Reserve should work")
	}

	// scanner should give two regions
	regions = make([]string, 0)
	scanner = func(start, end int) {
		regions = append(regions, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	layout.ScanFreeRegions(scanner, endPos)
	if regions[0] != "0:3" {
		t.Error("First free byteRangeForAllowedPositionIndex should be 0:3, was", regions[0])
	}
	if regions[1] != "203:1000" {
		t.Error("Second free byteRangeForAllowedPositionIndex should be 203:1000, was", regions[1])
	}
}
