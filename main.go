package main

import (
	"github.com/puerco/vexi/pkg/vexi"
	"github.com/sirupsen/logrus"
)

func main() {
	generator := vexi.NewGenerator()
	err := generator.ImageVEX("cgr.dev/chainguard/curl@sha256:fa5292b1973e8a6b57fd9e7809526d7484dc37749ecff1402e6493d797ed3e24")
	if err != nil {
		logrus.Fatalf("generating image VEX: %s", err)
	}
}
