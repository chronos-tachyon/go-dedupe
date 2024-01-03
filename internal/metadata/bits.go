package metadata

import "fmt"

type Bits uint32

const (
	SizeBit Bits = (1 << iota)
	TimeBit
	MD5Bit
	SHA1Bit
	SHA256Bit
)

const NumBits = 5

const AllBits = Bits(1<<NumBits) - 1

var metadataBitGoNames = [NumBits]string{
	"SizeBit",
	"TimeBit",
	"MD5Bit",
	"SHA1Bit",
	"SHA256Bit",
}

var metadataBitNames = [NumBits]string{
	"size",
	"time",
	"md5",
	"sha1",
	"sha256",
}

func (bits Bits) Has(x Bits) bool {
	return (bits & x) != 0
}

func (bits Bits) HasAll(x Bits) bool {
	return (bits & x) == x
}

func (bits Bits) appendImpl(out []byte, names [NumBits]string, sep string) []byte {
	if bits == 0 {
		return append(out, '0')
	}

	needSep := false
	for i := uint(0); i < NumBits; i++ {
		name := names[i]
		bit := Bits(1) << i
		if !bits.Has(bit) {
			continue
		}
		if needSep {
			out = append(out, sep...)
		}
		out = append(out, name...)
		needSep = true
	}
	if bits.Has(^AllBits) {
		if needSep {
			out = append(out, sep...)
		}
		out = fmt.Appendf(out, "%#x", uint32(bits & ^AllBits))
	}
	return out
}

func (bits Bits) GoAppend(out []byte) []byte {
	return bits.appendImpl(out, metadataBitGoNames, "|")
}

func (bits Bits) Append(out []byte) []byte {
	return bits.appendImpl(out, metadataBitNames, "|")
}

func (bits Bits) GoString() string {
	var scratch [256]byte
	return string(bits.GoAppend(scratch[:0]))
}

func (bits Bits) String() string {
	var scratch [256]byte
	return string(bits.Append(scratch[:0]))
}

var (
	_ fmt.GoStringer = Bits(0)
	_ fmt.Stringer   = Bits(0)
)
