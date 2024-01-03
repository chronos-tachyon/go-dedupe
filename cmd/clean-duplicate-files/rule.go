package main

import (
	"regexp"

	"github.com/chronos-tachyon/go-dedupe/internal/glob"
)

type Rule struct {
	Pattern *regexp.Regexp
}

func (rule Rule) Matches(path string) bool {
	return rule.Pattern.MatchString(path)
}

type Rules []Rule

func (list Rules) Priority(path string) uint {
	path = glob.Normalize(path)
	i := uint(0)
	listLen := uint(len(list))
	for i < listLen {
		if list[i].Matches(path) {
			break
		}
		i++
	}
	return i
}
