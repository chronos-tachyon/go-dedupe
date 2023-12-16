package main

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

type KeyList []Key

func (x KeyList) Len() int {
	return len(x)
}

func (x KeyList) Less(i, j int) bool {
	a, b := x[i], x[j]
	return a.CompareTo(b) < 0
}

func (x KeyList) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}
