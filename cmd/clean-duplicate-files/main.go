package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/chronos-tachyon/go-autolog"
	"github.com/rs/zerolog/log"

	"github.com/chronos-tachyon/go-dedupe/internal/glob"
)

const tempDirPattern = ".incoming.*"

var (
	flagRel   bool
	flagRules Rules
)

func init() {
	flag.BoolVar(&flagRel, "rel", false, "use relative paths when generating symlinks")
	flag.Func("prefer", "glob pattern to match", func(in string) error {
		rx, err := glob.Compile(in)
		if err != nil {
			return err
		}
		flagRules = append(flagRules, Rule{Pattern: rx})
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

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	var data [][]string
	err = json.Unmarshal(raw, &data)
	if err != nil {
		panic(err)
	}

	for _, paths := range data {
		processBatch(paths)
	}
}

func processBatch(paths []string) {
	if len(paths) <= 1 {
		return
	}

	var items Items
	defer func() {
		for _, it := range items {
			it.Close()
		}
	}()

	items = make(Items, 0, len(paths))
	for _, path := range paths {
		items = append(items, Open(path))
	}
	items.Sort()

	var best *Item
	index := uint(0)
	itemsLen := uint(len(items))
	for index < itemsLen {
		best = items[index]
		if !best.IsSymlink {
			break
		}
		index++
	}
	if index >= itemsLen {
		return
	}

	for _, it := range items {
		if it == best {
			continue
		}
		if os.SameFile(it.Info, best.Info) && !it.IsSymlink {
			continue
		}

		log.Logger.Debug().
			Str("src", best.Path).
			Str("dst", it.Path).
			Msg("replacing duplicate file with link")

		ok := tryLink(best.Path, it.Path)
		if !ok {
			ok = trySymlink(best.Path, it.Path)
		}
		if !ok {
			log.Logger.Fatal().
				Msg("exiting due to previous failures")
			panic(nil)
		}
	}
}

func tryLink(srcPath string, dstPath string) bool {
	dstName := filepath.Base(dstPath)
	dstDir := filepath.Dir(dstPath)

	tempDir, err := os.MkdirTemp(dstDir, tempDirPattern)
	if err != nil {
		log.Logger.Error().
			Str("path", filepath.Join(dstDir, tempDirPattern)).
			Err(err).
			Msg("failed to create temporary directory")
		return false
	}

	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Logger.Error().
				Str("path", tempDir).
				Err(err).
				Msg("failed to delete temporary directory")
		}
	}()

	tempPath := filepath.Join(tempDir, dstName)
	err = os.Link(srcPath, tempPath)
	if errors.Is(err, syscall.EXDEV) {
		return false
	}
	if err != nil {
		log.Logger.Error().
			Str("path", tempPath).
			Str("target", srcPath).
			Err(err).
			Msg("failed to create link")
		return false
	}

	_ = os.Remove(dstPath)
	err = os.Rename(tempPath, dstPath)
	if err != nil {
		log.Logger.Error().
			Str("path", tempPath).
			Str("target", dstPath).
			Err(err).
			Msg("failed to rename temporary file to final name")
		return false
	}

	return true
}

func trySymlink(srcPath string, dstPath string) bool {
	srcAbs, err := filepath.Abs(srcPath)
	if err != nil {
		log.Logger.Error().
			Str("path", srcPath).
			Err(err).
			Msg("failed to make target path absolute")
		return false
	}

	dstName := filepath.Base(dstPath)
	dstDir := filepath.Dir(dstPath)

	srcLink := srcAbs
	if flagRel {
		srcLink, err = filepath.Rel(dstDir, srcAbs)
		if err != nil {
			log.Logger.Error().
				Str("base", dstDir).
				Str("target", srcAbs).
				Err(err).
				Msg("failed to make target path relative to destination directory")
			return false
		}
	}

	tempDir, err := os.MkdirTemp(dstDir, tempDirPattern)
	if err != nil {
		log.Logger.Error().
			Str("path", filepath.Join(dstDir, tempDirPattern)).
			Err(err).
			Msg("failed to create temporary directory")
		return false
	}

	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Logger.Error().
				Str("path", tempDir).
				Err(err).
				Msg("failed to delete temporary directory")
		}
	}()

	tempPath := filepath.Join(tempDir, dstName)
	err = os.Symlink(srcLink, tempPath)
	if err != nil {
		log.Logger.Error().
			Str("path", tempPath).
			Str("target", srcLink).
			Err(err).
			Msg("failed to create symlink")
		return false
	}

	_ = os.Remove(dstPath)
	err = os.Rename(tempPath, dstPath)
	if err != nil {
		log.Logger.Error().
			Str("path", tempPath).
			Str("target", dstPath).
			Err(err).
			Msg("failed to rename temporary symlink to final name")
		return false
	}

	return true
}
