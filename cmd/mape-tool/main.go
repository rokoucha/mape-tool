package main

import (
	"fmt"
	"os"

	"github.com/rokoucha/mape-tool/internal/app"
)

func main() {
	if err := app.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "mape-tool: %v\n", err)
		os.Exit(1)
	}
}
