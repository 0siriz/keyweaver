package main

import (
	"fmt"
	"os"

	"github.com/0siriz/keyweaver/internal/cmd/kw"
)

func main() {
	if err := kw.NewCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
