package vexi

import (
	"fmt"

	"github.com/puerco/vexi/pkg/vexi/options"
	"github.com/sirupsen/logrus"
)

type Generator struct {
	impl    generatorImplementation
	Options options.Options
}

func NewGenerator() *Generator {
	return &Generator{
		impl:    &defaultVexiImplementation{},
		Options: options.Default,
	}
}

type PackageList []string
type AdvisoryList map[string]string

func (gen *Generator) ImageVEX(imageRef string) error {
	if err := gen.impl.ValidateOptions(&gen.Options); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	// Of we are working on a temporary directory, it needs to be cloned
	if gen.Options.IsTempDir {
		logrus.Info("cloning advisory data...")
		if err := gen.impl.CloneAdvisoryRepo(gen.Options); err != nil {
			return fmt.Errorf("cloning advisory data: %w", err)
		}
	}

	sboms, err := gen.impl.DownloadSBOM(gen.Options, imageRef)
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

	nodelist, err := gen.impl.FilterSBOMPackages(protobom)
	if err != nil {
		return fmt.Errorf("filtering SBOM packages: %w", err)
	}
	logrus.Infof("Found %d wolfi packages in image SBOM", len(nodelist.Nodes))

	advisories, err := gen.impl.FindPackageAdvisories(gen.Options, nodelist)
	if err != nil {
		return fmt.Errorf("searching advisory data: %w", err)
	}
	logrus.Infof("Found %d package advisories", len(advisories))

	vexDocuments, err := gen.impl.GenerateVEXData(advisories)
	if err != nil {
		return fmt.Errorf("generating VEX data: %w", err)
	}
	logrus.Infof("Built %d OpenVEX documents from advisories", len(vexDocuments))

	vexDocument, err := gen.impl.MergeDocuments(vexDocuments)
	if err != nil {
		return fmt.Errorf("merging VEX documents: %w", err)
	}

	if err := gen.impl.WriteVexDocument(vexDocument); err != nil {
		return fmt.Errorf("writing vex doc to stream: %w", err)
	}
	return nil
}
