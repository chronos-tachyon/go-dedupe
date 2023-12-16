package main

import "crypto/sha256"

func CompareByte(a byte, b byte) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func CompareUint64(a uint64, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func CompareSHA256(a SHA256Sum, b SHA256Sum) int {
	for i := 0; i < sha256.Size; i++ {
		ai, bi := a[i], b[i]
		if cmp := CompareByte(ai, bi); cmp != 0 {
			return cmp
		}
	}
	return 0
}
