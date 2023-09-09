package vexi

import (
	"fmt"
	"os"
	"strings"

	purl "github.com/package-url/packageurl-go"
	"github.com/puerco/deployer/pkg/deploy"
	"github.com/puerco/deployer/pkg/payload"
	"github.com/sirupsen/logrus"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/openvex/go-vex/pkg/vex"
)

type generatorImplementation interface {
	DownloadSBOM(Options, string) (os.File, error)
	ParseSBOM(os.File) (*sbom.Document, error)
	FilterSBOMPackages(*sbom.Document) (PackageList, error)
	FindPackageAdvisories(PackageList) (AdvisoryList, error)
	GenerateVEXData(AdvisoryList) ([]*vex.VEX, error)
	MergeDocuments([]*vex.VEX) (*vex.VEX, error)
	WriteVexDocument(*vex.VEX) error
}

type defaultVexiImplementation struct{}

// purlFromRef returns a purl capturing the image reference
func purlFromRef(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}

	digestVersion := ""

	if digest, ok := ref.(name.Digest); ok {
		digestVersion = digest.DigestStr()
	}

	qMap := map[string]string{}

	tag, ok := ref.(name.Tag)
	tagString := ""
	if ok {
		tagString = tag.TagStr()
		// If the tag is latest, then make sure it is in the original
		// reference string. Do not add it to the purl if it was inferred
		if tagString == "latest" {
			if !strings.HasSuffix(imageRef, ":latest") && !strings.Contains(imageRef, ":latest@") {
				tagString = ""
			}
		}
	}

	if tagString != "" {
		qMap["tag"] = tagString
	}

	parts := strings.Split(ref.Context().Name(), "/")
	name := parts[len(parts)-1]

	repoURL := ""
	if len(parts) > 1 {
		repoURL = strings.Join(parts[0:len(parts)-1], "/")
		if parts[0] == "index.docker.io" {
			if !strings.Contains(imageRef, "index.docker.io/library") {
				repoURL = ""
			}
		}
	}

	if repoURL != "" {
		qMap["repository_url"] = repoURL
	}

	p := purl.NewPackageURL(
		purl.TypeOCI,  // Always set to "oci"
		"",            // OCI purls don't have a namespace
		name,          // Name of the image, no slashes
		digestVersion, // We only add the digest as version if it was set in the original string
		purl.QualifiersFromMap(qMap),
		"",
	)

	purlString := p.ToString()

	// This is a bug in the purl go implementation:
	purlString = strings.ReplaceAll(purlString, "@sha256:", "@sha256%3A")
	return purlString, nil
}

// DownloadSBOM retrieves all the SBOMs associated with the image.
func (dvi *defaultVexiImplementation) DownloadSBOM(opts Options, imageRef string) ([]*payload.Document, error) {
	// Use the mighty deployer to drop any SBOMs from the image to vexi
	probe := deploy.NewProbe()

	probe.Options.Formats = payload.FormatsList{
		payload.Format("text/spdx"),
		payload.Format("application/vnd.cyclonedx"),
	}

	purlString, err := purlFromRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("translating image reference to package URL: %w", err)
	}

	docs, err := probe.Fetch(purlString)
	if err != nil {
		fmt.Fprintf(os.Stdout, "fetching documents: %s\n", err)
		os.Exit(1)
	}

	logrus.Infof("Downloaded %d SBOMs from image %s", len(docs), imageRef)

	return docs, nil
}
