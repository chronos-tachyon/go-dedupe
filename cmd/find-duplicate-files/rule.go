package main

import (
	"bytes"
	"regexp"

	"github.com/chronos-tachyon/go-dedupe/internal/glob"
	"github.com/chronos-tachyon/go-dedupe/internal/item"
	"github.com/chronos-tachyon/go-dedupe/internal/metadata"
)

type Rule struct {
	Pattern *regexp.Regexp
	Exclude bool
}

func (rule Rule) Matches(path string) bool {
	return rule.Pattern.MatchString(path)
}

type Rules []Rule

func (list Rules) Exclude(it *item.Item) bool {
	if raw, ok := metadata.MaybeFGet(it.File, flagNS+"exclude"); ok {
		switch {
		case len(raw) <= 0:
			fallthrough
		case bytes.Equal(raw, []byte("1")):
			fallthrough
		case bytes.Equal(raw, []byte("y")):
			fallthrough
		case bytes.Equal(raw, []byte("yes")):
			fallthrough
		case bytes.Equal(raw, []byte("t")):
			fallthrough
		case bytes.Equal(raw, []byte("true")):
			return true

		default:
			return false
		}
	}

	path := glob.Normalize(it.Path)
	for _, rule := range list {
		if rule.Matches(path) {
			return rule.Exclude
		}
	}
	return false
}
