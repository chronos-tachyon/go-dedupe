package metadata

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

type (
	MD5Sum    = [md5.Size]byte
	SHA1Sum   = [sha1.Size]byte
	SHA256Sum = [sha256.Size]byte
)
