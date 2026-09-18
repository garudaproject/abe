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

package main

import (
	"fmt"
	"os"
	"slices"

	"github.com/garudaproject/abe"
)

var version = "dev"

const banner = `
         __ %s
  ____ _/ /_  ___
 / __ '/ __ \/ _ \
/ /_/ / /_/ /  __/
\__,_/_.___/\___/
`

func usage() {
	fmt.Print(fmt.Sprintf(banner, version), `
Usage: abe <command> <file> [password]

Commands:
  unpack    Extract an Android backup (.ab) to a tar archive
  pack      Create an Android backup (.ab) from a tar archive

Flags:
  -h, -help   Show help message
`)
}

func main() {
	var mode, file, pass string
	for i, arg := range os.Args {
		if slices.Contains([]string{"-h", "--help"}, arg) {
			usage()
			return
		}
		switch i {
		case 1:
			mode = arg
		case 2:
			file = arg
		case 3:
			pass = arg
		}
	}
	if mode == "" || file == "" {
		usage()
		return
	}
	switch mode {
	case "unpack":
		if err := abe.Unpack(file, pass); err != nil {
			fmt.Println("Err:", err)
			os.Exit(1)
		}
		fmt.Println("Unpacking: successfully")
	case "pack":
		if err := abe.Pack(file, pass); err != nil {
			fmt.Println("Err:", err)
			os.Exit(1)
		}
		fmt.Println("Packing: successfully")
	default:
		fmt.Println("Err: Unsupported")
		os.Exit(1)
	}
}
