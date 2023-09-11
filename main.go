package main

import (
	"os"

	"github.com/puerco/vexi/internal/cli"
	"github.com/sirupsen/logrus"
)

func main() {
	err := cli.Execute()
	if err != nil {
		logrus.Fatal(err)
		os.Exit(1)
	}
}
