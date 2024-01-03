package glob

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	rxSlash    = `/+`
	rxQuestion = `[^/]`
	rxStar     = `[^/]*`
	rxStarStar = `.*`
)

type compilerState byte

const (
	stateDone compilerState = iota
	stateReady
	stateSlash
	stateOpenBracket
	stateQuestion
	stateStar
	stateOpenBrace
	stateComma
	stateCloseBrace
)

var globCompilerStateNames = [...]string{
	"stateDone",
	"stateReady",
	"stateSlash",
	"stateOpenBracket",
	"stateQuestion",
	"stateStar",
	"stateOpenBrace",
	"stateComma",
	"stateCloseBrace",
}

func (state compilerState) GoString() string {
	return globCompilerStateNames[state]
}

func (state compilerState) String() string {
	return globCompilerStateNames[state]
}

type Compiler struct {
	err     error
	input   string
	output  []byte
	depth   uint
	char    rune
	hasChar bool
	state   compilerState
}

func (gc *Compiler) peekRune() (rune, bool) {
	if gc.err == nil && !gc.hasChar {
		ch, size := utf8.DecodeRuneInString(gc.input)
		if size > 1 || (size == 1 && ch >= 0 && ch != utf8.RuneError) {
			gc.input = gc.input[size:]
			gc.char = ch
			gc.hasChar = true
		}
	}
	return gc.char, gc.hasChar
}

func (gc *Compiler) consumeRune(expect rune) {
	if gc.err != nil {
		panic(fmt.Errorf("BUG: consumeRune(%q) after fail(%q)", expect, gc.err))
	}
	ch, ok := gc.peekRune()
	if !ok {
		panic(fmt.Errorf("BUG: expected %q; got EOF", expect))
	}
	if ch != expect {
		panic(fmt.Errorf("BUG: expected %q; got %q", expect, ch))
	}
	gc.hasChar = false
	gc.char = -1
}

func (gc *Compiler) fail(err error) bool {
	if gc.err != nil {
		panic(fmt.Errorf("BUG: fail(%q) after fail(%q)", err, gc.err))
	}
	gc.err = err
	gc.input = ""
	gc.depth = 0
	gc.char = -1
	gc.hasChar = false
	gc.state = stateDone
	return false
}

func (gc *Compiler) failf(msg string, args ...any) bool {
	return gc.fail(fmt.Errorf(msg, args...))
}

func (gc *Compiler) requireEOF() bool {
	if gc.err != nil {
		return false
	}
	if len(gc.input) > 0 {
		return gc.failf("invalid UTF-8 in pattern: %v", []byte(gc.input[:8]))
	}
	if gc.depth > 0 {
		return gc.failf("expected depth=0; got depth=%d", gc.depth)
	}
	gc.output = append(gc.output, '$')
	return gc.fail(io.EOF)
}

func (gc *Compiler) onReady() bool {
	ch, ok := gc.peekRune()
	if !ok {
		return gc.requireEOF()
	}
	switch {
	case ch == '\\':
		return gc.failf("unexpected character '\\'")
	case ch == '/':
		gc.state = stateSlash
	case ch == '*':
		gc.state = stateStar
	case ch == '?':
		gc.state = stateQuestion
	case ch == '[':
		gc.state = stateOpenBracket
	case ch == '{':
		gc.state = stateOpenBrace
	case ch == ',' && gc.depth > 0:
		gc.state = stateComma
	case ch == '}' && gc.depth > 0:
		gc.state = stateCloseBrace
	default:
		gc.consumeRune(ch)
		quoted := regexp.QuoteMeta(string(ch))
		gc.output = append(gc.output, quoted...)
	}
	return true
}

func (gc *Compiler) onSlash() bool {
	gc.consumeRune('/')
	ch, ok := gc.peekRune()
	for ok && ch == '/' {
		gc.consumeRune(ch)
		ch, ok = gc.peekRune()
	}
	gc.output = append(gc.output, rxSlash...)
	gc.state = stateReady
	return true
}

func (gc *Compiler) onBracket() bool {
	gc.consumeRune('[')
	gc.output = append(gc.output, '[')

	if ch, ok := gc.peekRune(); ok && ch == '^' {
		gc.consumeRune('^')
		gc.output = append(gc.output, '^')
	}

	inEscape := false
	looping := true
	for looping {
		ch, ok := gc.peekRune()
		if !ok {
			return gc.failf("invalid character match [ab...]: %w", io.ErrUnexpectedEOF)
		}

		switch {
		case inEscape:
			gc.consumeRune(ch)
			gc.output = append(gc.output, '\\')
			gc.output = utf8.AppendRune(gc.output, ch)
			inEscape = false

		case ch == '\\':
			gc.consumeRune('\\')
			inEscape = true

		case ch == ']':
			gc.consumeRune(']')
			gc.output = append(gc.output, ']')
			looping = false

		default:
			gc.consumeRune(ch)
			gc.output = utf8.AppendRune(gc.output, ch)
		}
	}

	gc.state = stateReady
	return true
}

func (gc *Compiler) onQuestion() bool {
	gc.consumeRune('?')
	gc.output = append(gc.output, rxQuestion...)
	gc.state = stateReady
	return true
}

func (gc *Compiler) onStar() bool {
	gc.consumeRune('*')
	pattern := rxStar
	if ch, ok := gc.peekRune(); ok && ch == '*' {
		gc.consumeRune('*')
		pattern = rxStarStar
	}
	gc.output = append(gc.output, pattern...)
	gc.state = stateReady
	return true
}

func (gc *Compiler) onOpenBrace() bool {
	gc.consumeRune('{')
	gc.output = append(gc.output, '(', '?', ':')
	gc.depth++
	gc.state = stateReady
	return true
}

func (gc *Compiler) onComma() bool {
	gc.consumeRune(',')
	gc.output = append(gc.output, '|')
	gc.state = stateReady
	return true
}

func (gc *Compiler) onCloseBrace() bool {
	gc.consumeRune('}')
	gc.output = append(gc.output, ')')
	gc.depth--
	gc.state = stateReady
	return true
}

func (gc *Compiler) step() bool {
	switch gc.state {
	case stateDone:
		return false
	case stateReady:
		return gc.onReady()
	case stateSlash:
		return gc.onSlash()
	case stateOpenBracket:
		return gc.onBracket()
	case stateQuestion:
		return gc.onQuestion()
	case stateStar:
		return gc.onStar()
	case stateOpenBrace:
		return gc.onOpenBrace()
	case stateComma:
		return gc.onComma()
	case stateCloseBrace:
		return gc.onCloseBrace()
	default:
		panic(fmt.Errorf("BUG: %v not implemented", gc.state))
	}
}

func (gc *Compiler) Reset(input string) {
	if gc.output == nil {
		gc.output = make([]byte, 0, len(input)*2+2)
	} else {
		gc.output = gc.output[:0]
	}

	gc.input = input
	gc.err = nil
	gc.state = stateReady
	gc.depth = 0
	gc.hasChar = false
	gc.char = -1
	gc.output = append(gc.output, '^')
}

func (gc *Compiler) Run() {
	for gc.step() {
	}
}

func (gc *Compiler) Compile() (*regexp.Regexp, error) {
	if gc.err == nil {
		panic("BUG")
	}
	if gc.err == io.EOF {
		return regexp.Compile(string(gc.output))
	}
	return nil, gc.err
}

func Compile(input string) (rx *regexp.Regexp, err error) {
	input = norm.NFD.String(input)
	if strings.HasPrefix(input, "^") {
		return regexp.Compile(input)
	}
	var gc Compiler
	gc.Reset(input)
	gc.Run()
	return gc.Compile()
}

func Normalize(path string) string {
	path = filepath.Clean(path)
	path = filepath.ToSlash(path)
	path = norm.NFD.String(path)
	return path
}
