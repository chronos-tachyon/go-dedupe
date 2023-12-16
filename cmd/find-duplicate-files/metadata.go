package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/pkg/xattr"
)

const (
	xaStamp  = "user.stamp"
	xaSize   = "user.size"
	xaMTime  = "user.mtime"
	xaMD5    = "user.md5sum"
	xaSHA1   = "user.sha1sum"
	xaSHA256 = "user.sha256sum"

	rxB64StdLetter   = `[0-9A-Za-z+/]`
	rxB64StdWord     = `(?:` + rxB64StdLetter + `{4})`
	rxB64StdLastWord = `(?:` + rxB64StdLetter + `{3}=|` + rxB64StdLetter + `{2}==)`
	rxB64Std         = rxB64StdWord + `*` + rxB64StdLastWord + `?`

	rxB64URLLetter   = `[0-9A-Za-z_-]`
	rxB64URLWord     = `(?:` + rxB64URLLetter + `{4})`
	rxB64URLLastWord = `(?:` + rxB64URLLetter + `{3}=|` + rxB64URLLetter + `{2}==)`
	rxB64URL         = rxB64URLWord + `*` + rxB64URLLastWord + `?`
)

var (
	kSplit   = []byte(",")
	kCut     = []byte(":")
	kSize    = []byte("size")
	kModTime = []byte("modTime")
	kMD5     = []byte("md5")
	kSHA1    = []byte("sha1")
	kSHA256  = []byte("sha256")

	reInt    = regexp.MustCompile(`^(?:0|[1-9][0-9]+)$`)
	reHex    = regexp.MustCompile(`^([0-9A-FA-f][0-9A-Fa-f])*$`)
	reB64Std = regexp.MustCompile(`^` + rxB64Std + `$`)
	reB64URL = regexp.MustCompile(`^` + rxB64URL + `$`)
)

type (
	MD5Sum    = [md5.Size]byte
	SHA1Sum   = [sha1.Size]byte
	SHA256Sum = [sha256.Size]byte
)

type Metadata struct {
	Size    int64
	ModTime int64
	MD5     MD5Sum
	SHA1    SHA1Sum
	SHA256  SHA256Sum
}

func (md *Metadata) Load(file *os.File) (bool, error) {
	*md = Metadata{}

	raw, found, err := MaybeFGet(file, xaStamp)
	if err != nil {
		return false, err
	}
	if found && md.Decode(raw) {
		return true, nil
	}

	hasSize := false
	hasModTime := false
	hasMD5 := false
	hasSHA1 := false
	hasSHA256 := false

	raw, found, err = MaybeFGet(file, xaSize)
	if err != nil {
		return false, err
	}
	if found && DecodeInt(&md.Size, raw) {
		hasSize = true
	}

	raw, found, err = MaybeFGet(file, xaMTime)
	if err != nil {
		return false, err
	}
	if found && DecodeInt(&md.ModTime, raw) {
		hasModTime = true
	}

	raw, found, err = MaybeFGet(file, xaMD5)
	if err != nil {
		return false, err
	}
	if found && DecodeHash(md.MD5[:], raw) {
		hasMD5 = true
	}

	raw, found, err = MaybeFGet(file, xaSHA1)
	if err != nil {
		return false, err
	}
	if found && DecodeHash(md.SHA1[:], raw) {
		hasSHA1 = true
	}

	raw, found, err = MaybeFGet(file, xaSHA256)
	if err != nil {
		return false, err
	}
	if found && DecodeHash(md.SHA256[:], raw) {
		hasSHA256 = true
	}

	ok := hasSize && hasModTime && hasMD5 && hasSHA1 && hasSHA256
	return ok, nil
}

func (md *Metadata) Compute(file *os.File, size int64, modTime time.Time) error {
	*md = Metadata{}

	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("%q: failed to rewind file to start: %w", file.Name(), err)
	}

	var computedSize int64
	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()

	for {
		var buf [1 << 16]byte
		n, err := file.Read(buf[:])
		if n > 0 {
			p := buf[:n]
			computedSize += int64(n)
			_, _ = md5Hasher.Write(p)
			_, _ = sha1Hasher.Write(p)
			_, _ = sha256Hasher.Write(p)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%q: failed to read file: %w", file.Name(), err)
		}
	}

	if size != computedSize {
		return fmt.Errorf("%q: file size changed while computing hash: expected to read %d bytes, but actually read %d bytes", file.Name(), size, computedSize)
	}

	md.Size = size
	md.ModTime = UnixTime(modTime)
	_ = md5Hasher.Sum(md.MD5[:0])
	_ = sha1Hasher.Sum(md.SHA1[:0])
	_ = sha256Hasher.Sum(md.SHA256[:0])
	return nil
}

func (md *Metadata) Decode(input []byte) (ok bool) {
	*md = Metadata{}
	hasSize := false
	hasModTime := false
	hasMD5 := false
	hasSHA1 := false
	hasSHA256 := false
	for _, raw := range bytes.Split(input, kSplit) {
		key, value, found := bytes.Cut(raw, kCut)
		switch {
		case found && bytes.EqualFold(key, kSize):
			if DecodeInt(&md.Size, value) {
				hasSize = true
			}
		case found && bytes.EqualFold(key, kModTime):
			if DecodeInt(&md.ModTime, value) {
				hasModTime = true
			}
		case found && bytes.EqualFold(key, kMD5):
			if DecodeHash(md.MD5[:], value) {
				hasMD5 = true
			}
		case found && bytes.EqualFold(key, kSHA1):
			if DecodeHash(md.SHA1[:], value) {
				hasSHA1 = true
			}
		case found && bytes.EqualFold(key, kSHA256):
			if DecodeHash(md.SHA256[:], value) {
				hasSHA256 = true
			}
		}
	}
	return hasSize && hasModTime && hasMD5 && hasSHA1 && hasSHA256
}

func (md Metadata) Save(file *os.File) error {
	var tmp [64]byte
	if err := xattr.FSet(file, xaStamp, md.Encode(tmp[:0])); err != nil {
		return fmt.Errorf("%q: failed to set xattr %q: %w", file.Name(), xaStamp, err)
	}
	if err := xattr.FSet(file, xaSize, EncodeInt(tmp[:], md.Size)); err != nil {
		return fmt.Errorf("%q: failed to set xattr %q: %w", file.Name(), xaSize, err)
	}
	if err := xattr.FSet(file, xaMTime, EncodeInt(tmp[:], md.ModTime)); err != nil {
		return fmt.Errorf("%q: failed to set xattr %q: %w", file.Name(), xaMTime, err)
	}
	if err := xattr.FSet(file, xaMD5, EncodeHash(tmp[:], md.MD5[:])); err != nil {
		return fmt.Errorf("%q: failed to set xattr %q: %w", file.Name(), xaMD5, err)
	}
	if err := xattr.FSet(file, xaSHA1, EncodeHash(tmp[:], md.SHA1[:])); err != nil {
		return fmt.Errorf("%q: failed to set xattr %q: %w", file.Name(), xaSHA1, err)
	}
	if err := xattr.FSet(file, xaSHA256, EncodeHash(tmp[:], md.SHA256[:])); err != nil {
		return fmt.Errorf("%q: failed to set xattr %q: %w", file.Name(), xaSHA256, err)
	}
	return nil
}

func (md Metadata) Check(size int64, modTime time.Time) bool {
	unixTime := UnixTime(modTime)
	return size == md.Size && unixTime == md.ModTime
}

func (md Metadata) Encode(out []byte) []byte {
	var tmp [64]byte
	out = append(out, kSize...)
	out = append(out, kCut...)
	out = append(out, EncodeInt(tmp[:], md.Size)...)
	out = append(out, kSplit...)
	out = append(out, kModTime...)
	out = append(out, kCut...)
	out = append(out, EncodeInt(tmp[:], md.ModTime)...)
	out = append(out, kSplit...)
	out = append(out, kMD5...)
	out = append(out, kCut...)
	out = append(out, EncodeHash(tmp[:], md.MD5[:])...)
	out = append(out, kSplit...)
	out = append(out, kSHA1...)
	out = append(out, kCut...)
	out = append(out, EncodeHash(tmp[:], md.SHA1[:])...)
	out = append(out, kSplit...)
	out = append(out, kSHA256...)
	out = append(out, kCut...)
	out = append(out, EncodeHash(tmp[:], md.SHA256[:])...)
	return out
}

func (md Metadata) String() string {
	var tmp [64]byte
	return string(md.Encode(tmp[:0]))
}

func UnixTime(t time.Time) int64 {
	return t.Truncate(time.Second).Unix()
}

func MaybeFGet(file *os.File, name string) ([]byte, bool, error) {
	raw, err := xattr.FGet(file, name)
	if err == nil {
		return raw, true, nil
	}
	if errors.Is(err, xattr.ENOATTR) {
		return nil, false, nil
	}
	if errors.Is(err, syscall.ENODATA) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("%q: failed to read xattr %q: %w", file.Name(), name, err)
}

func DecodeInt(output *int64, input []byte) bool {
	if reInt.Match(input) {
		str := string(input)
		i64, err := strconv.ParseInt(str, 10, 64)
		if err == nil {
			*output = i64
			return true
		}
	}
	if len(input) == 8 {
		*output = int64(binary.BigEndian.Uint64(input))
		return true
	}
	return false
}

func EncodeInt(tmp []byte, value int64) []byte {
	return strconv.AppendInt(tmp[:0], value, 10)
}

func DecodeHash(output []byte, input []byte) bool {
	inputLen := len(input)
	outputLen := len(output)

	if inputLen == outputLen {
		copy(output, input)
		return true
	}

	if inputLen >= hex.EncodedLen(outputLen) && reHex.Match(input) {
		n, err := hex.Decode(output, input)
		if n == outputLen && err == nil {
			return true
		}
	}

	if inputLen >= base64.StdEncoding.EncodedLen(outputLen) {
		if reB64Std.Match(input) {
			n, err := base64.StdEncoding.Decode(output, input)
			if n == outputLen && err == nil {
				return true
			}
		}
		if reB64URL.Match(input) {
			n, err := base64.URLEncoding.Decode(output, input)
			if n == outputLen && err == nil {
				return true
			}
		}
	}

	return false
}

func EncodeHash(tmp []byte, raw []byte) []byte {
	n := base64.StdEncoding.EncodedLen(len(raw))
	if len(tmp) < n {
		tmp = make([]byte, n)
	}
	base64.StdEncoding.Encode(tmp, raw)
	return tmp[:n]
}
