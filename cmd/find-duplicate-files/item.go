package main

import (
	"github.com/chronos-tachyon/go-dedupe/internal/item"
)

type Item = item.Item

func Open(path string) *Item {
	return item.Open(path)
}
