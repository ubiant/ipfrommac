package main

import (
	"fmt"
	"os"

	"github.com/ubiant/ipfrommac"
)

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		os.Exit(22)
	}
	ip, err := ipfrommac.IpFromMac(args[0], args[1])
	if err != nil {
		os.Exit(6)
	}
	fmt.Println(ip)
}
