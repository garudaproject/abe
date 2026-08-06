package main

import (
	"archive/tar"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

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

func readString(f io.Reader) (string, error) {
	buf := new(bytes.Buffer)
	char := make([]byte, 1)
	for {
		_, err := f.Read(char)
		if err != nil || err == io.EOF {
			return "", err
		}
		if bytes.Equal(char, []byte{10}) {
			break
		}
		_, _ = buf.Write(char)
	}
	return buf.String(), nil
}

func decompress(in io.Reader, out string) error {
	reader, err := zlib.NewReader(in)
	if err != nil {
		return err
	}
	defer reader.Close()
	outf, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outf.Close()
	_, err = io.Copy(outf, reader)
	return err
}

func compress(in string, out io.Writer) error {
	writer := zlib.NewWriter(out)
	defer writer.Close()
	input, err := os.Open(in)
	if err != nil {
		return err
	}
	defer input.Close()
	_, err = io.Copy(writer, input)
	if err != nil {
		return err
	}
	return writer.Flush()
}

func hashFiles(dir string, files ...string) error {
	root, err := filepath.Rel(".", dir)
	if err != nil {
		return err
	}
	md5hash := func(filename string) (string, error) {
		file, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		defer file.Close()
		md := md5.New()
		if _, err := io.Copy(md, file); err != nil {
			return "", err
		}
		hash := hex.EncodeToString(md.Sum(nil))
		fmt.Println("Hashing:", hash, filename)
		return hash, nil
	}
	hashes := map[string]string{}
	if err := filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			hash, err := md5hash(path)
			if err != nil {
				return err
			}
			hashes[path] = hash
		}
		return nil
	}); err != nil {
		return err
	}
	for _, file := range files {
		hash, err := md5hash(file)
		if err != nil {
			return err
		}
		hashes[file] = hash
	}
	file, err := os.OpenFile("hash.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	for k, v := range hashes {
		if _, err := fmt.Fprintf(file, "%s %s\n", v, k); err != nil {
			return err
		}
	}
	fmt.Println("Hashing written: hash.txt")
	return nil
}

func decodeHex(s string) []byte {
	dec, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		log.Panicln(err)
	}
	return dec
}

func pkcs7Unpaded(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, errors.New("invalid padding")
	}
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	if subtle.ConstantTimeCompare(data[len(data)-padding:], pad) != 1 {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padding], nil
}

func decryptMasterBlob(hdr *Header, userKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(userKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(block, hdr.UserIV)
	plain := make([]byte, len(hdr.MasterBlob))
	cbc.CryptBlocks(plain, hdr.MasterBlob)
	return pkcs7Unpaded(plain, aes.BlockSize)
}

func verify(hdr *Header, key string, checksum []byte) error {
	expected, err := pbkdf2.Key(sha1.New, key, hdr.ChecksumSalt, hdr.Rounds, len(checksum))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, checksum) != 1 {
		return errors.New("checksum does not match")
	}
	return nil
}

func toJavaString(data []byte) string {
	str := new(bytes.Buffer)
	buf := make([]byte, 4)
	for i := range data {
		b := uint16(data[i])
		if int8(data[i]) < 0 {
			b |= 0xFF00
		}
		rb := utf16.Decode([]uint16{b})
		n := utf8.EncodeRune(buf, rb[0])
		str.Write(buf[:n])
	}
	return str.String()
}

func decrypt(in io.Reader, out io.Writer, mk *MasterKey) error {
	block, err := aes.NewCipher(mk.Key)
	if err != nil {
		return err
	}
	cbc := cipher.NewCBCDecrypter(block, mk.IV)
	buf := make([]byte, aes.BlockSize)
	for {
		n, err := in.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		cbc.CryptBlocks(buf[:n], buf[:n])
		if _, err := out.Write(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

func unpackTar(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		head, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		fmt.Println("Unpack:", head.Name)
		switch head.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(head.Name, os.FileMode(head.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(head.Name), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(head.Name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(head.Mode))
			if err != nil {
				return err
			}
			defer out.Close()
			if _, err := io.Copy(out, reader); err != nil {
				return err
			}
			if err := os.Chtimes(head.Name, head.AccessTime, head.ModTime); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeHeader(in io.Reader) (*Header, error) {
	var err error
	hdr := new(Header)
	hdr.Magick, err = readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read magick header failed")
	}
	if hdr.Magick != MagickHeader {
		return nil, fmt.Errorf("Invalid file format")
	}
	ver, err := readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read version failed")
	}
	hdr.Version, _ = strconv.Atoi(string(ver))
	if hdr.Version < 1 || hdr.Version > VersionMax {
		return nil, fmt.Errorf("Only supported version 1-5")
	}
	comp, err := readString(in)
	hdr.Compressed = comp == "1"
	if err != nil {
		return nil, fmt.Errorf("Read compressed failed")
	}
	hdr.Encryption, err = readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read algorithm failed")
	}
	return hdr, nil
}

func decodeMasterKey(in io.Reader, hdr *Header, pass string) (*MasterKey, error) {
	uslt, err := readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read user salt failed")
	}
	hdr.UserSalt = decodeHex(string(uslt))
	ckslt, err := readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read checksum salt failed")
	}
	hdr.ChecksumSalt = decodeHex(string(ckslt))
	rnds, err := readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read rounds failed")
	}
	hdr.Rounds, _ = strconv.Atoi(string(rnds))
	usriv, err := readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read user iv failed")
	}
	hdr.UserIV = decodeHex(string(usriv))
	mtrbob, err := readString(in)
	if err != nil {
		return nil, fmt.Errorf("Read master blob failed")
	}
	hdr.MasterBlob = decodeHex(string(mtrbob))
	userKey, err := pbkdf2.Key(sha1.New, pass, hdr.UserSalt, hdr.Rounds, 32)
	if err != nil {
		return nil, err
	}
	masterBlob, err := decryptMasterBlob(hdr, userKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt, password invalid")
	}
	masterKey := new(MasterKey)
	reader := bytes.NewReader(masterBlob)
	var offset int64
	masterKey.IV = make([]byte, masterBlob[0])
	n, err := reader.ReadAt(masterKey.IV, offset+1)
	if err != nil {
		return nil, fmt.Errorf("failed to read master iv")
	}
	offset += int64(n + 1)
	masterKey.Key = make([]byte, masterBlob[offset])
	n, err = reader.ReadAt(masterKey.Key, offset+1)
	if err != nil {
		return nil, fmt.Errorf("failed to read master key")
	}
	offset += int64(n + 1)
	masterKey.Checksum = make([]byte, masterBlob[offset])
	_, err = reader.ReadAt(masterKey.Checksum, offset+1)
	if err != nil {
		return nil, fmt.Errorf("failed to read master checksum")
	}
	if err := verify(hdr, toJavaString(masterKey.Key), masterKey.Checksum); err != nil {
		return nil, err
	}
	return masterKey, nil
}

func unpackAb(abfile, pass string) error {
	in, err := os.Open(abfile)
	if err != nil {
		return err
	}
	defer in.Close()
	hdr, err := decodeHeader(in)
	if err != nil {
		return err
	}
	fmt.Println("Header:", hdr.Magick)
	fmt.Println("Version:", hdr.Version)
	fmt.Println("Compressed:", hdr.Compressed)
	fmt.Println("Algorithm:", hdr.Encryption)
	_, abname := path.Split(abfile)
	tarname := strings.ReplaceAll(abname, ".ab", ".tar")
	switch hdr.Encryption {
	case NONE:
		if err := decompress(in, tarname); err != nil {
			return fmt.Errorf("failed to decompress %s", err)
		}
		if err := unpackTar(tarname); err != nil {
			return fmt.Errorf("failed to unpack tar %s", err)
		}
		if err := hashFiles("apps", tarname); err != nil {
			return fmt.Errorf("failed to hashing file %s", err)
		}
	case AES256:
		if pass == "" {
			return fmt.Errorf("\nPassword required!")
		}
		masterKey, err := decodeMasterKey(in, hdr, pass)
		if err != nil {
			return err
		}
		tmpname := strings.ReplaceAll(abname, ".ab", ".tmp")
		tmp, err := os.OpenFile(tmpname, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer tmp.Close()
		defer os.Remove(tmp.Name())
		if err := decrypt(in, tmp, masterKey); err != nil {
			return fmt.Errorf("failed to decrypt")
		}
		out, err := os.OpenFile(tarname, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer out.Close()
		tmp.Seek(0, io.SeekStart)
		if err := decompress(tmp, tarname); err != nil {
			return fmt.Errorf("failed to decompress %s", err)
		}
		out.Seek(0, io.SeekStart)
		if err := unpackTar(tarname); err != nil {
			return fmt.Errorf("failed to unpack tar %s", err)
		}
		if err := hashFiles("apps", tarname); err != nil {
			return fmt.Errorf("failed to hashing file %s", err)
		}
	default:
		return fmt.Errorf("Unsupported")
	}
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Panicln(err)
	}
	return b
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func encryptBlob(plain, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func encrypt(in io.Reader, out io.Writer, mk *MasterKey) error {
	block, err := aes.NewCipher(mk.Key)
	if err != nil {
		return err
	}
	cbc := cipher.NewCBCEncrypter(block, mk.IV)
	buf := make([]byte, aes.BlockSize)
	pend := make([]byte, aes.BlockSize)
	hasPend := false
	write := func(data []byte) error {
		cbc.CryptBlocks(data, data)
		_, err := out.Write(data)
		return err
	}
	for {
		n, err := io.ReadFull(in, buf)
		switch {
		case err == io.EOF:
			if hasPend {
				if err := write(pend); err != nil {
					return err
				}
			}
			return write(bytes.Repeat([]byte{byte(aes.BlockSize)}, aes.BlockSize))
		case err == io.ErrUnexpectedEOF:
			if hasPend {
				if err := write(pend); err != nil {
					return err
				}
			}
			padding := byte(aes.BlockSize - n)
			for i := n; i < aes.BlockSize; i++ {
				buf[i] = padding
			}
			return write(buf)
		case err != nil:
			return err
		}
		if hasPend {
			if err := write(pend); err != nil {
				return err
			}
		}
		copy(pend, buf)
		hasPend = true
	}
}

func packAesHeader(out io.Writer, pass string) (*MasterKey, error) {
	userSalt := randomBytes(SaltSize)
	checksumSalt := randomBytes(SaltSize)
	userKey, err := pbkdf2.Key(sha1.New, pass, userSalt, Rounds, KeySize)
	if err != nil {
		return nil, err
	}
	userIv := randomBytes(aes.BlockSize)
	mk := &MasterKey{
		IV:  randomBytes(aes.BlockSize),
		Key: randomBytes(KeySize),
	}
	checksum, err := pbkdf2.Key(sha1.New, toJavaString(mk.Key), checksumSalt, Rounds, KeySize)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 0, 1+len(mk.IV)+1+len(mk.Key)+1+len(checksum))
	blob = append(blob, byte(len(mk.IV)))
	blob = append(blob, mk.IV...)
	blob = append(blob, byte(len(mk.Key)))
	blob = append(blob, mk.Key...)
	blob = append(blob, byte(len(checksum)))
	blob = append(blob, checksum...)
	encBlob, err := encryptBlob(blob, userKey, userIv)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(out, "%s\n%s\n%d\n%s\n%s\n",
		hex.EncodeToString(userSalt), hex.EncodeToString(checksumSalt),
		Rounds, hex.EncodeToString(userIv), hex.EncodeToString(encBlob)); err != nil {
		return nil, err
	}
	return mk, nil
}

func packAb(tarfile string, pass string) error {
	tmpname := strings.ReplaceAll(tarfile, ".tar", ".tmp")
	zfile, err := os.OpenFile(tmpname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer zfile.Close()
	defer os.Remove(tmpname)
	if err := compress(tarfile, zfile); err != nil {
		return err
	}
	abname := strings.ReplaceAll(tarfile, ".tar", ".ab")
	abfile, err := os.OpenFile(abname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer abfile.Close()
	abfile.Write([]byte(MagickHeader))
	abfile.Write([]byte{10})
	fmt.Fprintf(abfile, "%d", VersionMax)
	abfile.Write([]byte{10})
	fmt.Fprintf(abfile, "%d", Compressed)
	abfile.Write([]byte{10})
	if pass == "" {
		abfile.Write([]byte(NONE))
		abfile.Write([]byte{10})
		zfile.Seek(0, io.SeekStart)
		if _, err := io.Copy(abfile, zfile); err != nil {
			return err
		}
		return nil
	}
	abfile.Write([]byte(AES256))
	abfile.Write([]byte{10})
	masterKey, err := packAesHeader(abfile, pass)
	if err != nil {
		return err
	}
	zfile.Seek(0, io.SeekStart)
	return encrypt(zfile, abfile, masterKey)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println(`Usage: abe unpack <backup.ab> <password>
       abe pack <backup.tar> <password>

Notes: password is optional`)
		return
	}

	mode := os.Args[1]
	file := os.Args[2]
	pass := ""
	if len(os.Args) >= 4 {
		pass = os.Args[3]
	}

	switch mode {
	case "unpack":
		if err := unpackAb(file, pass); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Unpacking: successfully")
	case "pack":
		if err := packAb(file, pass); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Packing: successfully")
	default:
		fmt.Println("Unsupported")
	}
}
