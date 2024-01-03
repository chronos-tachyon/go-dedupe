package item

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

func UnixTime(t time.Time) int64 {
	return t.Truncate(time.Second).Unix()
}

type Item struct {
	Path      string
	File      *os.File
	Info      fs.FileInfo
	Mode      fs.FileMode
	Size      int64
	Time      int64
	Dev       uint64
	Ino       uint64
	Nlink     uint64
	Priority  uint
	IsSymlink bool
}

func Open(path string) *Item {
	path = filepath.Clean(path)

	f, err := os.Open(path)
	if err != nil {
		log.Logger.Error().
			Str("path", path).
			Err(err).
			Msg("failed to open file")
		return nil
	}

	fi, err := f.Stat()
	if err != nil {
		log.Logger.Error().
			Str("path", path).
			Err(err).
			Msg("failed to stat file")
		return nil
	}

	var item Item
	item.Path = path
	item.File = f
	item.Info = fi
	item.Mode = fi.Mode()
	item.Size = fi.Size()
	item.Time = UnixTime(fi.ModTime())
	if x, ok := fi.Sys().(*syscall.Stat_t); ok {
		item.Dev = x.Dev
		item.Ino = x.Ino
		item.Nlink = uint64(x.Nlink)
	}
	return &item
}

func (item *Item) Close() {
	if item == nil {
		return
	}

	f := item.File
	item.File = nil
	if f != nil {
		if err := f.Close(); err != nil {
			log.Logger.Error().
				Str("path", item.Path).
				Err(err).
				Msg("failed to close file")
		}
	}
}
