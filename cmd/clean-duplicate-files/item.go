package main

import (
	"cmp"
	"os"
	"sort"

	"github.com/rs/zerolog/log"

	"github.com/chronos-tachyon/go-dedupe/internal/item"
)

type Item = item.Item

func Open(path string) *Item {
	it := item.Open(path)
	if it == nil {
		return nil
	}
	if it.Mode.Type() != 0 {
		it.Close()
		return nil
	}
	it.Priority = flagRules.Priority(it.Path)
	it.IsSymlink = true

	fi, err := os.Lstat(it.Path)
	if err != nil {
		log.Logger.Warn().
			Str("path", it.Path).
			Err(err).
			Msg("lstat failed")
		return it
	}
	it.IsSymlink = (fi.Mode() != it.Mode)
	return it
}

func CompareItems(a *Item, b *Item) int {
	order := cmp.Compare(a.Priority, b.Priority)
	if order == 0 {
		order = -cmp.Compare(a.Nlink, b.Nlink)
	}
	if order == 0 {
		order = cmp.Compare(a.Time, b.Time)
	}
	if order == 0 {
		order = cmp.Compare(a.Path, b.Path)
	}
	return order
}

type Items []*Item

func (list Items) Len() int {
	return len(list)
}

func (list Items) Less(i, j int) bool {
	order := CompareItems(list[i], list[j])
	return order < 0
}

func (list Items) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list Items) Sort() {
	sort.Sort(list)
}
