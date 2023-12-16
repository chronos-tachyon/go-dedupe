package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

var (
	flagRescan  bool
	flagRewrite bool
)

func init() {
	flag.BoolVar(&flagRescan, "rescan", false, "don't trust memoized hashes at all")
	flag.BoolVar(&flagRewrite, "rewrite", false, "upgrade memoized hashes to current format")
}

func main() {
	flag.Parse()

	stack := make(Stack[Item], 0, 256)
	defer func() {
		for !stack.IsEmpty() {
			item := stack.Pop()
			_ = item.Close()
		}
	}()

	for _, rootPath := range flag.Args() {
		var item Item
		if err := item.Open(filepath.Clean(rootPath)); err != nil {
			panic(err)
		}
		stack.Push(item)
	}

	seen := make(map[Key][]string, 1<<20)
	for !stack.IsEmpty() {
		if err := Scan(&stack, seen, stack.Pop()); err != nil {
			panic(err)
		}
	}

	keys := make([]Key, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Sort(KeyList(keys))

	seenByHash := make(map[SHA256Sum][]string, len(keys))
	for _, key := range keys {
		subPaths := seen[key]
		sort.Strings(subPaths)

		paths := seenByHash[key.Hash]
		if paths == nil {
			paths = make([]string, 0, 1)
		}
		paths = append(paths, subPaths[0])
		seenByHash[key.Hash] = paths
	}

	hashes := make([]SHA256Sum, 0, len(seenByHash))
	for hash := range seenByHash {
		hashes = append(hashes, hash)
	}
	sort.Sort(SHA256List(hashes))

	results := make([][]string, 0, len(hashes))
	for _, hash := range hashes {
		paths := seenByHash[hash]
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

func Scan(stack *Stack[Item], seen map[Key][]string, item Item) error {
	switch item.Info.Mode().Type() {
	case 0:
		return ScanFile(seen, item)
	case fs.ModeDir:
		return ScanDir(stack, seen, item)
	default:
		return item.Close()
	}
}

func ScanDir(stack *Stack[Item], seen map[Key][]string, item Item) error {
	needClose := true
	defer func() {
		if needClose {
			_ = item.Close()
		}
	}()

	dents, err := item.File.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("%q: failed to read directory: %w", item.Path, err)
	}

	for _, dent := range dents {
		fileName := dent.Name()
		if fileName == "." || fileName == ".." {
			continue
		}

		fileType := dent.Type()
		switch fileType {
		case 0:
			// pass
		case fs.ModeDir:
			// pass
		default:
			continue
		}

		var child Item
		if err := child.Open(filepath.Join(item.Path, fileName)); err != nil {
			return err
		}

		fileType2 := child.Info.Mode().Type()
		if fileType != fileType2 {
			_ = child.Close()
			return fmt.Errorf("%q: file type mismatch: ReadDir said %v, but Stat said %v", child.Path, fileType, fileType2)
		}

		if fileType == fs.ModeDir {
			stack.Push(child)
			continue
		}

		if err := ScanFile(seen, child); err != nil {
			return err
		}
	}

	needClose = false
	return item.Close()
}

func ScanFile(seen map[Key][]string, item Item) error {
	needClose := true
	defer func() {
		if needClose {
			_ = item.Close()
		}
	}()

	var md Metadata
	loaded := false
	if !flagRescan {
		ok, err := md.Load(item.File)
		if err != nil {
			return err
		}
		loaded = ok
	}

	size := item.Info.Size()
	modTime := item.Info.ModTime()
	dirty := false
	if !loaded || !md.Check(size, modTime) {
		if err := md.Compute(item.File, size, modTime); err != nil {
			return err
		}
		dirty = true
	}

	if dirty || flagRewrite {
		if err := md.Save(item.File); err != nil {
			return err
		}
	}

	key := Key{Hash: md.SHA256, Dev: item.Dev, Ino: item.Ino}
	list := seen[key]
	if list == nil {
		list = make([]string, 0, 1)
	}
	list = append(list, item.Path)
	seen[key] = list

	needClose = false
	return item.Close()
}

type Key struct {
	Hash SHA256Sum
	Dev  uint64
	Ino  uint64
}

func (key Key) CompareTo(other Key) int {
	cmp := CompareSHA256(key.Hash, other.Hash)
	if cmp == 0 {
		cmp = CompareUint64(key.Dev, other.Dev)
	}
	if cmp == 0 {
		cmp = CompareUint64(key.Ino, other.Ino)
	}
	return cmp
}
