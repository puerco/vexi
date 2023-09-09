package vexi

import (
	"fmt"
)

type Generator struct {
	impl generatorImplementation
	opts Options
}
type Options struct {
	Platform           string
	PredicateTypesList string
}

type PackageList []string
type AdvisoryList map[string]string

func (gen *Generator) GenerateImageVEX(imageRef string) error {
	sbom, err := gen.impl.DownloadSBOM(gen.opts, imageRef)
	if err != nil {
		return fmt.Errorf("downloading image SBOM: %w", err)
	}

	protobom, err := gen.impl.ParseSBOM(sbom)
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
