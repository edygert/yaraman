package main

import (
	"strings"
)

// MapSet is a map used to emulate a set.
// To add a member: s.Add(value).
// To test if a value is a member of set "s":
// 	if s[value] {
// 		do stuff
// 	}
// To remove a value: s.Remove(value)
type MapSet map[string]bool

// Add adds a string to the set.
func (map1 MapSet) Add(v string) {
	map1[v] = true
}

// Remove removes a string from the set.
func (map1 MapSet) Remove(v string) {
	delete(map1, v)
}

// Contains tests for the presence of a value in the set
func (map1 MapSet) Contains(v string) bool {
	_, ok := map1[v]
	return ok
}

// Join returns a string of all the entries separated by the specified separator.
func (map1 MapSet) Join(separator string) string {
	var builder strings.Builder

	first := true
	for k := range map1 {
		if !first {
			builder.WriteString(separator)
		}
		first = false
		builder.WriteString(k)
	}

	return builder.String()
}

// Intersection returns a new MapSet that is the intersection
// of the receiver and the passed in map.
func (map1 MapSet) Intersection(map2 MapSet) MapSet {
	intersect := MapSet{}
	for k := range map1 {
		if map2[k] {
			intersect[k] = true
		}
	}
	return intersect
}

// Union returns a new MapSet that is the union
// of the receiver and the passed in map.
func (map1 MapSet) Union(map2 MapSet) MapSet {
	union := MapSet{}
	for k := range map1 {
		union[k] = true
	}
	for k := range map2 {
		union[k] = true
	}
	return union
}

// Minus returns a new MapSet that is the entries
// of the receiver minus the entries of the passed in map.
func (map1 MapSet) Minus(map2 MapSet) MapSet {
	minus := MapSet{}
	for k := range map1 {
		if !map2[k] {
			minus[k] = true
		}
	}
	return minus
}

// AddFrom adds all of map2's entries to the receiver.
func (map1 MapSet) AddFrom(map2 MapSet) {
	for k := range map2 {
		map1[k] = true
	}
}

// AddFromSlice adds all of slice's entries to the receiver.
func (map1 MapSet) AddFromSlice(s []string) {
	for _, v := range s {
		map1.Add(v)
	}
}

// Subtract subtracts all of map2's entries from the receiver.
func (map1 MapSet) Subtract(map2 MapSet) {
	for k := range map2 {
		delete(map1, k)
	}
}
