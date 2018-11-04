package purbs

import (
	"testing"
	"strconv"
)

func TestSkipList(t *testing.T) {

	layout := NewRangeReservationLayout()

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
		t.Error("First free region should be 0:10")
	}
	if regions[1] != "100:1000" {
		t.Error("Second free region should be 100:1000")
	}

	// overlapping reservation should fail is requireFree is asked
	success = layout.Reserve(50, 200, true, "block50-200")
	if success {
		t.Error("Reserve should not work")
	}
	layout.dump()

	// non-overlapping reservation should succeed
	success = layout.Reserve(150, 200, true, "block150-200")
	if success {
		t.Error("Reserve should work")
	}

	// scanner should give two regions
	regions = make([]string, 0)
	scanner = func(start, end int) {
		regions = append(regions, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	layout.ScanFreeRegions(scanner, endPos)
	if regions[0] != "0:10" {
		t.Error("First free region should be 0:10")
	}
	if regions[1] != "100:150" {
		t.Error("Second free region should be 100:150")
	}
	if regions[2] != "200:1000" {
		t.Error("Third free region should be 200:1000")
	}

}