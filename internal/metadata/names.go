package metadata

type Names struct {
	Stamp  string
	Size   string
	Time   string
	MD5    string
	SHA1   string
	SHA256 string
}

func DefaultNames() Names {
	return Names{
		Stamp:  "user.dedupe.stamp",
		Size:   "user.size",
		Time:   "user.mtime",
		MD5:    "user.md5sum",
		SHA1:   "user.sha1sum",
		SHA256: "user.sha256sum",
	}
}
