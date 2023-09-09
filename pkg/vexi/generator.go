package vexi

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type Generator struct {
	impl generatorImplementation
	opts Options
}

func NewGenerator() *Generator {
	return &Generator{
		impl: &defaultVexiImplementation{},
		opts: Options{},
	}
}

type Options struct {
	Platform           string
	PredicateTypesList string
}

type PackageList []string
type AdvisoryList map[string]string

func (gen *Generator) ImageVEX(imageRef string) error {
	sboms, err := gen.impl.DownloadSBOM(gen.opts, imageRef)
	if err != nil {
		return fmt.Errorf("downloading image SBOM: %w", err)
	}

	if len(sboms) == 0 {
		logrus.Infof("No SBOMs found when probing image %s", imageRef)
		return nil
	}

	protobom, err := gen.impl.ParseSBOM(sboms[0])
	if err != nil {
		return fmt.Errorf("parsing image SBOM: %w", err)
	}

	packages, err := gen.impl.FilterSBOMPackages(protobom)
	if err != nil {
		return fmt.Errorf("filtering SBOM packages: %w", err)
	}

	advisories, err := gen.impl.FindPackageAdvisories(packages)
	if err != nil {
		return fmt.Errorf("")
	}

	vexDocuments, err := gen.impl.GenerateVEXData(advisories)
	if err != nil {
		return fmt.Errorf("generating VEX data: %w", err)
	}

	vexDocument, err := gen.impl.MergeDocuments(vexDocuments)
	if err != nil {
		return fmt.Errorf("merging VEX documents: %w", err)
	}

	if err := gen.impl.WriteVexDocument(vexDocument); err != nil {
		return fmt.Errorf("writing vex doc to stream: %w", err)
	}
	return nil
}
