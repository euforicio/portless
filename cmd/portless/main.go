package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}

	fmt.Fprintln(os.Stderr, "portless: implementation in progress")
	fmt.Fprintln(os.Stderr, "usage: portless version")
	os.Exit(2)
}
