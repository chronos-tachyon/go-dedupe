package metadata

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"github.com/rs/zerolog/log"
)

var (
	kSplit   = []byte(",")
	kCut     = []byte(":")
	kSize    = []byte("size")
	kModTime = []byte("modTime")
	kMD5     = []byte("md5")
	kSHA1    = []byte("sha1")
	kSHA256  = []byte("sha256")

	reHex    = regexp.MustCompile(`^(?:[0-9A-FA-f]{2})*$`)
	reB64Std = regexp.MustCompile(`^(?:[0-9A-Za-z+/]{4})*(?:[0-9A-Za-z+/]{3}=|[0-9A-Za-z+/]{2}==)?$`)
	reB64URL = regexp.MustCompile(`^(?:[0-9A-Za-z_-]{4})*(?:[0-9A-Za-z_-]{3}=|[0-9A-Za-z_-]{2}==)?$`)
)

type Metadata struct {
	Bits   Bits
	Size   int64
	Time   int64
	MD5    MD5Sum
	SHA1   SHA1Sum
	SHA256 SHA256Sum
}

func (meta *Metadata) Reset() {
	*meta = Metadata{}
}

func (meta Metadata) Check(size int64, modTime int64) bool {
	if meta.Bits.HasAll(SizeBit | TimeBit) {
		if size == meta.Size && modTime == meta.Time {
			return true
		}
	}
	return false
}

func (meta *Metadata) Load(file *os.File, names Names) bool {
	if raw, ok := MaybeFGet(file, names.Stamp); ok {
		meta.Decode(raw)
	}
	if !meta.Bits.Has(SizeBit) {
		if raw, ok := MaybeFGet(file, names.Size); ok {
			meta.decodeSize(raw)
		}
	}
	if !meta.Bits.Has(TimeBit) {
		if raw, ok := MaybeFGet(file, names.Time); ok {
			meta.decodeModTime(raw)
		}
	}
	if !meta.Bits.Has(MD5Bit) {
		if raw, ok := MaybeFGet(file, names.MD5); ok {
			meta.decodeMD5(raw)
		}
	}
	if !meta.Bits.Has(SHA1Bit) {
		if raw, ok := MaybeFGet(file, names.SHA1); ok {
			meta.decodeSHA1(raw)
		}
	}
	if !meta.Bits.Has(SHA256Bit) {
		if raw, ok := MaybeFGet(file, names.SHA256); ok {
			meta.decodeSHA256(raw)
		}
	}
	return meta.Bits.HasAll(AllBits)
}

func (meta *Metadata) Decode(input []byte) bool {
	for _, raw := range bytes.Split(input, kSplit) {
		key, value, found := bytes.Cut(raw, kCut)
		switch {
		case found && bytes.EqualFold(key, kSize):
			meta.decodeSize(value)
		case found && bytes.EqualFold(key, kModTime):
			meta.decodeModTime(value)
		case found && bytes.EqualFold(key, kMD5):
			meta.decodeMD5(value)
		case found && bytes.EqualFold(key, kSHA1):
			meta.decodeSHA1(value)
		case found && bytes.EqualFold(key, kSHA256):
			meta.decodeSHA256(value)
		}
	}
	return meta.Bits.HasAll(AllBits)
}

func (meta *Metadata) decodeSize(raw []byte) {
	if i64, ok := decodeInt(raw); ok {
		meta.Size = i64
		meta.Bits |= SizeBit
		return
	}
	log.Logger.Warn().Bytes("value", raw).Msg("failed to decode size")
}

func (meta *Metadata) decodeModTime(raw []byte) {
	if i64, ok := decodeInt(raw); ok {
		meta.Time = i64
		meta.Bits |= TimeBit
		return
	}
	log.Logger.Warn().Bytes("value", raw).Msg("failed to decode last modified time")
}

func (meta *Metadata) decodeMD5(raw []byte) {
	var sum MD5Sum
	if decodeHash(sum[:], raw) {
		meta.MD5 = sum
		meta.Bits |= MD5Bit
		return
	}
	log.Logger.Warn().Bytes("value", raw).Msg("failed to decode MD5 hash")
}

func (meta *Metadata) decodeSHA1(raw []byte) {
	var sum SHA1Sum
	if decodeHash(sum[:], raw) {
		meta.SHA1 = sum
		meta.Bits |= SHA1Bit
		return
	}
	log.Logger.Warn().Bytes("value", raw).Msg("failed to decode SHA1 hash")
}

func (meta *Metadata) decodeSHA256(raw []byte) {
	var sum SHA256Sum
	if decodeHash(sum[:], raw) {
		meta.SHA256 = sum
		meta.Bits |= SHA256Bit
		return
	}
	log.Logger.Warn().Bytes("value", raw).Msg("failed to decode SHA256 hash")
}

func decodeInt(input []byte) (int64, bool) {
	if i64, err := strconv.ParseInt(string(input), 10, 64); err == nil {
		return i64, true
	}
	if len(input) == 8 {
		i64 := int64(binary.BigEndian.Uint64(input))
		return i64, true
	}
	return 0, false
}

func decodeHash(output []byte, input []byte) bool {
	inputLen := len(input)
	outputLen := len(output)
	if inputLen == outputLen {
		copy(output, input)
		return true
	}
	if inputLen >= hex.EncodedLen(outputLen) {
		n, err := hex.Decode(output, input)
		if n == outputLen && err == nil {
			return true
		}
	}
	if inputLen >= base64.StdEncoding.EncodedLen(outputLen) {
		n, err := base64.StdEncoding.Decode(output, input)
		if n == outputLen && err == nil {
			return true
		}
		n, err = base64.URLEncoding.Decode(output, input)
		if n == outputLen && err == nil {
			return true
		}
	}
	return false
}

func (meta *Metadata) Compute(file *os.File, size int64, modTime int64) bool {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		log.Logger.Error().
			Str("path", file.Name()).
			Err(err).
			Msg("failed to rewind file to start")
		return false
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
			log.Logger.Error().
				Str("path", file.Name()).
				Int64("offset", computedSize).
				Err(err).
				Msg("I/O error while reading file")
			return false
		}
	}

	if size != computedSize {
		log.Logger.Warn().
			Str("path", file.Name()).
			Int64("expectedSize", size).
			Int64("computedSize", computedSize).
			Msg("file size changed while computing hash")
		return false
	}

	meta.Reset()
	meta.Bits = AllBits
	meta.Size = size
	meta.Time = modTime
	_ = md5Hasher.Sum(meta.MD5[:0])
	_ = sha1Hasher.Sum(meta.SHA1[:0])
	_ = sha256Hasher.Sum(meta.SHA256[:0])
	return true
}

func (meta Metadata) Save(file *os.File, names Names) {
	var scratch [64]byte
	MaybeFSet(file, names.Stamp, meta.Append(scratch[:0]))
	MaybeFSet(file, names.Size, appendInt(scratch[:0], meta.Size))
	MaybeFSet(file, names.Time, appendInt(scratch[:0], meta.Time))
	MaybeFSet(file, names.MD5, appendHash(scratch[:0], true, meta.MD5[:]))
	MaybeFSet(file, names.SHA1, appendHash(scratch[:0], true, meta.SHA1[:]))
	MaybeFSet(file, names.SHA256, appendHash(scratch[:0], true, meta.SHA256[:]))
}

func (meta Metadata) Append(out []byte) []byte {
	out = append(out, kSize...)
	out = append(out, kCut...)
	out = appendInt(out, meta.Size)
	out = append(out, kSplit...)
	out = append(out, kModTime...)
	out = append(out, kCut...)
	out = appendInt(out, meta.Time)
	out = append(out, kSplit...)
	out = append(out, kMD5...)
	out = append(out, kCut...)
	out = appendHash(out, false, meta.MD5[:])
	out = append(out, kSplit...)
	out = append(out, kSHA1...)
	out = append(out, kCut...)
	out = appendHash(out, false, meta.SHA1[:])
	out = append(out, kSplit...)
	out = append(out, kSHA256...)
	out = append(out, kCut...)
	out = appendHash(out, false, meta.SHA256[:])
	return out
}

func appendInt(out []byte, value int64) []byte {
	return strconv.AppendInt(out, value, 10)
}

func appendHash(out []byte, wantHex bool, raw []byte) []byte {
	var scratch [64]byte
	var tmp []byte
	if wantHex {
		n := hex.EncodedLen(len(raw))
		if n <= len(scratch) {
			tmp = scratch[:n]
		} else {
			tmp = make([]byte, n)
		}
		hex.Encode(tmp, raw)
	} else {
		n := base64.StdEncoding.EncodedLen(len(raw))
		if n <= len(scratch) {
			tmp = scratch[:n]
		} else {
			tmp = make([]byte, n)
		}
		base64.StdEncoding.Encode(tmp, raw)
	}
	return append(out, tmp...)
}

func (meta Metadata) String() string {
	var scratch [64]byte
	return string(meta.Append(scratch[:0]))
}

var _ fmt.Stringer = Metadata{}
