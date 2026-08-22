package main

const (
	MagickHeader = "ANDROID BACKUP"
	VersionMax   = 5
	Compressed   = 1
	NONE         = "none"
	AES256       = "AES-256"
	Rounds       = 10000
	SaltSize     = 512 / 8
	KeySize      = 256 / 8
)

type Header struct {
	Magick       string
	Version      int
	Compressed   bool
	Encryption   string
	UserSalt     []byte
	ChecksumSalt []byte
	Rounds       int
	UserIV       []byte
	MasterBlob   []byte
}

type MasterKey struct {
	IV       []byte
	Key      []byte
	Checksum []byte
}
