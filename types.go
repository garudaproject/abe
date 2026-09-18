/*
 * Copyright (c) 2026 Garuda Project
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
