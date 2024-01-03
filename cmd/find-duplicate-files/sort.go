package main

import "sort"

type SHA256List []SHA256Sum

func (x SHA256List) Len() int {
	return len(x)
}

func (x SHA256List) Less(i, j int) bool {
	a, b := x[i], x[j]
	return CompareSHA256(a, b) < 0
}

func (x SHA256List) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}

func (x SHA256List) Sort() {
	sort.Sort(x)
}
