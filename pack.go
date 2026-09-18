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
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Panicln(err)
	}
	return b
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

func Pack(tarfile string, pass string) error {
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
