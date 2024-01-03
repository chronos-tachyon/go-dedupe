package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/chronos-tachyon/go-autolog"
	"github.com/rs/zerolog/log"

	"github.com/chronos-tachyon/go-dedupe/internal/glob"
	"github.com/chronos-tachyon/go-dedupe/internal/metadata"
	"github.com/chronos-tachyon/go-dedupe/internal/stack"
)

type (
	MD5Sum    = metadata.MD5Sum
	SHA1Sum   = metadata.SHA1Sum
	SHA256Sum = metadata.SHA256Sum
	Stack     = stack.Stack[*Item]
)

var (
	flagXdev    bool
	flagRescan  bool
	flagRewrite bool
	flagMinSize int64
	flagNS      string
	flagRules   Rules
)

var gNames metadata.Names = metadata.DefaultNames()

func init() {
	flag.BoolVar(&flagXdev, "xdev", false, "don't recurse into different filesystems")
	flag.BoolVar(&flagRescan, "rescan", false, "don't trust memoized hashes at all")
	flag.Int64Var(&flagMinSize, "min-size", 1, "don't scan files with fewer bytes than this")
	flag.StringVar(&flagNS, "ns", "user.dedupe.", "xattr namespace to use")
	flag.Func("include", "glob pattern to include", func(in string) error {
		rx, err := glob.Compile(in)
		if err != nil {
			return err
		}
		flagRules = append(flagRules, Rule{Pattern: rx, Exclude: false})
		return nil
	})
	flag.Func("exclude", "glob pattern to exclude", func(in string) error {
		rx, err := glob.Compile(in)
		if err != nil {
			return err
		}
		flagRules = append(flagRules, Rule{Pattern: rx, Exclude: true})
		return nil
	})
}

func main() {
	autolog.Init()
	defer func() {
		err := autolog.Done()
		if err != nil {
			panic(err)
		}
	}()
	flag.Parse()
	gNames.Stamp = flagNS + "stamp"

	stack := make(Stack, 0, 256)
	defer func() {
		for !stack.IsEmpty() {
			stack.Pop().Close()
		}
	}()

	for _, rootPath := range flag.Args() {
		if it := Open(filepath.Clean(rootPath)); it != nil {
			stack.Push(it)
		}
	}

	seen := make(map[SHA256Sum][]string, 1<<20)
	for !stack.IsEmpty() {
		Scan(&stack, seen, stack.Pop())
	}

	hashes := make(SHA256List, 0, len(seen))
	for hash := range seen {
		hashes = append(hashes, hash)
	}
	hashes.Sort()

	results := make([][]string, 0, len(hashes))
	for _, hash := range hashes {
		paths := seen[hash]
		if len(paths) <= 1 {
			continue
		}
		results = append(results, paths)
	}

	stdout := bufio.NewWriter(os.Stdout)
	e := json.NewEncoder(stdout)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(results); err != nil {
		panic(err)
	}
	if err := stdout.Flush(); err != nil {
		panic(err)
	}
}

func Scan(stack *Stack, seen map[SHA256Sum][]string, it *Item) {
	defer it.Close()
	switch it.Mode.Type() {
	case 0:
		ScanFile(seen, it)
	case fs.ModeDir:
		ScanDir(stack, seen, it)
	}
}

func ScanDir(stack *Stack, seen map[SHA256Sum][]string, it *Item) {
	if flagRules.Exclude(it) {
		return
	}

	log.Logger.Debug().
		Str("path", it.Path).
		Msg("scan directory")

	dents, err := it.File.ReadDir(-1)
	if err != nil {
		log.Logger.Error().
			Str("path", it.Path).
			Err(err).
			Msg("failed to read directory")
		return
	}

	var child *Item
	for _, dent := range dents {
		fileName := dent.Name()
		if fileName == "." || fileName == ".." {
			continue
		}

		filePath := filepath.Join(it.Path, fileName)
		fileType := dent.Type()
		switch fileType {
		case 0:
			// pass
		case fs.ModeDir:
			// pass
		case fs.ModeSymlink:
			targetInfo, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			if targetType := targetInfo.Mode().Type(); targetType != 0 {
				continue
			}
			fileType = 0
		default:
			continue
		}

		child.Close()
		child = Open(filePath)
		if child == nil {
			continue
		}
		fileType2 := child.Mode.Type()

		if child.Dev != it.Dev {
			if flagXdev {
				continue
			}
			if fileType != fileType2 {
				continue
			}
		}

		if fileType != fileType2 {
			log.Logger.Error().
				Str("path", child.Path).
				Stringer("readDirType", fileType).
				Stringer("statType", fileType2).
				Msg("file type mismatch")
			continue
		}

		if fileType == fs.ModeDir {
			stack.Push(child)
			child = nil
			continue
		}

		ScanFile(seen, child)
	}
	child.Close()
}

func ScanFile(seen map[SHA256Sum][]string, it *Item) {
	if it.Size < flagMinSize {
		return
	}
	if flagRules.Exclude(it) {
		return
	}

	log.Logger.Debug().
		Str("path", it.Path).
		Msg("scan file")

	var meta metadata.Metadata
	hasAll := meta.Load(it.File, gNames)

	needRescan := flagRescan
	if !needRescan && !hasAll {
		log.Logger.Info().
			Str("path", it.Path).
			Str("reason", "missing metadata").
			Stringer("bitsFound", meta.Bits).
			Stringer("bitsMissing", metadata.AllBits&^meta.Bits).
			Msg("hash file")
		needRescan = true
	}
	if !needRescan && !meta.Check(it.Size, it.Time) {
		log.Logger.Info().
			Str("path", it.Path).
			Str("reason", "outdated metadata").
			Int64("oldSize", meta.Size).
			Int64("oldTime", meta.Time).
			Int64("newSize", it.Size).
			Int64("newTime", it.Time).
			Msg("hash file")
		needRescan = true
	}
	if needRescan {
		hasAll = meta.Compute(it.File, it.Size, it.Time)
	}
	if !hasAll {
		return
	}

	meta.Save(it.File, gNames)

	hash := meta.SHA256
	list := seen[hash]
	if list == nil {
		list = make([]string, 0, 1)
	}
	list = append(list, it.Path)
	seen[hash] = list
}
