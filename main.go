package main

import (
	"fmt"
	"os"
)

const usage = `
Usage: abe unpack <backup.ab> <password>
       abe pack <backup.tar> <password>

Notes: password is optional
`

func main() {
	if len(os.Args) < 3 {
		fmt.Print(usage)
		return
	}
	mode := os.Args[1]
	file := os.Args[2]
	var pass string
	if len(os.Args) >= 4 {
		pass = os.Args[3]
	}
	switch mode {
	case "unpack":
		if err := unpackAb(file, pass); err != nil {
			fmt.Println("Err:", err)
			os.Exit(1)
		}
		fmt.Println("Unpacking: successfully")
	case "pack":
		if err := packAb(file, pass); err != nil {
			fmt.Println("Err:", err)
			os.Exit(1)
		}
		fmt.Println("Packing: successfully")
	default:
		fmt.Println("Err: Unsupported")
		os.Exit(1)
	}
}
