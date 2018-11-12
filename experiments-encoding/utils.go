package main

import (
	"syscall"
	"log"
)

// Helpers for measurement of CPU cost of operations
type Monitor struct {
	CPUtime float64
}

func newMonitor() *Monitor {
	var m Monitor
	m.CPUtime = getCPUTime()
	return &m
}

func (m *Monitor) reset() {
	m.CPUtime = getCPUTime()
}

func (m *Monitor) record() float64 {
	return getCPUTime() - m.CPUtime
}

func (m *Monitor) recordAndReset() float64 {
	old := m.CPUtime
	m.CPUtime = getCPUTime()
	return m.CPUtime - old
}

// Returns the sum of the system and the user CPU time used by the current process so far.
	func getCPUTime() float64 {
	rusage := &syscall.Rusage{}
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, rusage); err != nil {
		log.Fatalln("Couldn't get rusage time:", err)
		return -1
	}
	s, u := rusage.Stime, rusage.Utime // system and user time
	return iiToF(int64(s.Sec), int64(s.Usec)) + iiToF(int64(u.Sec), int64(u.Usec))
}

// Converts to milliseconds
func iiToF(sec int64, usec int64) float64 {
	return float64(sec)*1000.0 + float64(usec)/1000.0
}
