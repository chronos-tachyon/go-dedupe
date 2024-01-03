package metadata

import (
	"bytes"
	"errors"
	"os"
	"syscall"

	"github.com/pkg/xattr"
	"github.com/rs/zerolog/log"
)

func MaybeFGet(file *os.File, name string) ([]byte, bool) {
	value, err := xattr.FGet(file, name)
	if err == nil {
		log.Logger.Trace().
			Str("path", file.Name()).
			Str("xaName", name).
			Bytes("xaValue", value).
			Msg("fgetxattr")
		return value, true
	}

	if errors.Is(err, xattr.ENOATTR) {
		return nil, false
	}

	if errors.Is(err, syscall.ENODATA) {
		return nil, false
	}

	log.Logger.Error().
		Str("path", file.Name()).
		Str("xaName", name).
		Err(err).
		Msg("fgetxattr failed")
	return nil, false
}

func MaybeFSet(file *os.File, name string, value []byte) {
	existing, err := xattr.FGet(file, name)
	switch {
	case err == nil:
		if bytes.Equal(value, existing) {
			return
		}
	case errors.Is(err, xattr.ENOATTR):
		// pass
	case errors.Is(err, syscall.ENODATA):
		// pass
	default:
		return
	}

	err = xattr.FSet(file, name, value)
	if err == nil {
		log.Logger.Debug().
			Str("path", file.Name()).
			Str("xaName", name).
			Bytes("xaValue", value).
			Msg("fsetxattr")
		return
	}

	log.Logger.Error().
		Str("path", file.Name()).
		Str("xaName", name).
		Bytes("xaValue", value).
		Err(err).
		Msg("fsetxattr failed")
}
