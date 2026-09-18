/*
 * Copyright (c) 2026 Garuda Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package abe

import (
	"archive/tar"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/pbkdf2"
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
		n, err := io.ReadFull(in, buf)
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
		return nil, errors.New("Read magick header failed")
	}
	if hdr.Magick != MagickHeader {
		return nil, errors.New("Invalid file format")
	}
	ver, err := readString(in)
	if err != nil {
		return nil, errors.New("Read version failed")
	}
	hdr.Version, _ = strconv.Atoi(string(ver))
	if hdr.Version < 1 || hdr.Version > VersionMax {
		return nil, errors.New("Only supported version 1-5")
	}
	comp, err := readString(in)
	hdr.Compressed = comp == "1"
	if err != nil {
		return nil, errors.New("Read compressed failed")
	}
	hdr.Encryption, err = readString(in)
	if err != nil {
		return nil, errors.New("Read algorithm failed")
	}
	return hdr, nil
}

func decodeMasterKey(in io.Reader, hdr *Header, pass string) (*MasterKey, error) {
	uslt, err := readString(in)
	if err != nil {
		return nil, errors.New("Read user salt failed")
	}
	hdr.UserSalt = decodeHex(string(uslt))
	ckslt, err := readString(in)
	if err != nil {
		return nil, errors.New("Read checksum salt failed")
	}
	hdr.ChecksumSalt = decodeHex(string(ckslt))
	rnds, err := readString(in)
	if err != nil {
		return nil, errors.New("Read rounds failed")
	}
	hdr.Rounds, _ = strconv.Atoi(string(rnds))
	usriv, err := readString(in)
	if err != nil {
		return nil, errors.New("Read user iv failed")
	}
	hdr.UserIV = decodeHex(string(usriv))
	mtrbob, err := readString(in)
	if err != nil {
		return nil, errors.New("Read master blob failed")
	}
	hdr.MasterBlob = decodeHex(string(mtrbob))
	userKey, err := pbkdf2.Key(sha1.New, pass, hdr.UserSalt, hdr.Rounds, 32)
	if err != nil {
		return nil, err
	}
	masterBlob, err := decryptMasterBlob(hdr, userKey)
	if err != nil {
		return nil, errors.New("failed to decrypt, password invalid")
	}
	masterKey := new(MasterKey)
	reader := bytes.NewReader(masterBlob)
	var offset int64
	masterKey.IV = make([]byte, masterBlob[0])
	n, err := reader.ReadAt(masterKey.IV, offset+1)
	if err != nil {
		return nil, errors.New("failed to read master iv")
	}
	offset += int64(n + 1)
	masterKey.Key = make([]byte, masterBlob[offset])
	n, err = reader.ReadAt(masterKey.Key, offset+1)
	if err != nil {
		return nil, errors.New("failed to read master key")
	}
	offset += int64(n + 1)
	masterKey.Checksum = make([]byte, masterBlob[offset])
	_, err = reader.ReadAt(masterKey.Checksum, offset+1)
	if err != nil {
		return nil, errors.New("failed to read master checksum")
	}
	if err := verify(hdr, toJavaString(masterKey.Key), masterKey.Checksum); err != nil {
		return nil, err
	}
	return masterKey, nil
}

func Unpack(abfile, pass string) error {
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
			return errors.New("\nPassword required!")
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
			return errors.New("failed to decrypt")
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
		return errors.New("Unsupported")
	}
	return nil
}
