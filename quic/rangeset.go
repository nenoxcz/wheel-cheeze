package quic

import (
	"slices"
	"sort"
)

// span is the half-open interval [start, end).
type span struct{ start, end uint64 }

func (s span) size() uint64 { return s.end - s.start }

// rangeSet is a sorted set of disjoint, non-adjacent spans. It tracks
// received packet numbers and sent, acknowledged or pending stream bytes.
type rangeSet []span

func (s *rangeSet) add(start, end uint64) {
	if start >= end {
		return
	}
	r := *s
	i := sort.Search(len(r), func(i int) bool { return r[i].end >= start })
	j := i
	for j < len(r) && r[j].start <= end {
		start = min(start, r[j].start)
		end = max(end, r[j].end)
		j++
	}
	*s = slices.Replace(r, i, j, span{start, end})
}

func (s *rangeSet) remove(start, end uint64) {
	if start >= end {
		return
	}
	r := *s
	i := sort.Search(len(r), func(i int) bool { return r[i].end > start })
	j := i
	var keep []span
	for j < len(r) && r[j].start < end {
		if r[j].start < start {
			keep = append(keep, span{r[j].start, start})
		}
		if r[j].end > end {
			keep = append(keep, span{end, r[j].end})
		}
		j++
	}
	*s = slices.Replace(r, i, j, keep...)
}

func (s rangeSet) contains(v uint64) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i].end > v })
	return i < len(s) && s[i].start <= v
}

// containsRange reports whether all of [start, end) is in the set.
func (s rangeSet) containsRange(start, end uint64) bool {
	if start >= end {
		return true
	}
	i := sort.Search(len(s), func(i int) bool { return s[i].end > start })
	return i < len(s) && s[i].start <= start && s[i].end >= end
}

func (s rangeSet) empty() bool { return len(s) == 0 }

// min returns the smallest element; the set must not be empty.
func (s rangeSet) min() uint64 { return s[0].start }

// max returns the largest element; the set must not be empty.
func (s rangeSet) max() uint64 { return s[len(s)-1].end - 1 }

// trimBelow removes everything below v.
func (s *rangeSet) trimBelow(v uint64) {
	if len(*s) > 0 && (*s)[0].start < v {
		s.remove(0, v)
	}
}
