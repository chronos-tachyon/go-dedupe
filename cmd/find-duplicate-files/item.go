package main

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

type Item struct {
	File *os.File
	Info fs.FileInfo
	Path string
	Dev  uint64
	Ino  uint64
}

func (item *Item) Open(path string) error {
	*item = Item{}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%q: failed to open file: %w", path, err)
	}
	fi, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%q: failed to stat file: %w", path, err)
	}
	item.File = file
	item.Info = fi
	item.Path = path
	if x, ok := fi.Sys().(*syscall.Stat_t); ok {
		item.Dev = x.Dev
		item.Ino = x.Ino
	}
	return nil
}

func (item *Item) Close() error {
	if file := item.File; file != nil {
		item.File = nil
		if err := file.Close(); err != nil {
			return fmt.Errorf("%q: failed to close file: %w", item.Path, err)
		}
	}
	return nil
}
