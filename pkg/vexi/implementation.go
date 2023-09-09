package vexi

import (
	"fmt"
	"os"
	"strings"

	purl "github.com/package-url/packageurl-go"
	"github.com/puerco/deployer/pkg/deploy"
	"github.com/puerco/deployer/pkg/payload"
	"github.com/puerco/vexi/pkg/vexi/options"
	"github.com/sirupsen/logrus"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"sigs.k8s.io/release-sdk/git"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/openvex/go-vex/pkg/vex"
)

type generatorImplementation interface {
	ValidateOptions(*options.Options) error
	CloneAdvisoryRepo(options.Options) error
	DownloadSBOM(options.Options, string) ([]*payload.Document, error)
	ParseSBOM(*payload.Document) (*sbom.Document, error)
	FilterSBOMPackages(*sbom.Document) (*sbom.NodeList, error)
	FindPackageAdvisories(options.Options, *sbom.NodeList) ([]v2.Document, error)
	GenerateVEXData([]v2.Document) ([]*vex.VEX, error)
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

// ValidateOptions calls the options validation function.
func (dvi *defaultVexiImplementation) ValidateOptions(opts *options.Options) error {
	return opts.Validate()
}

// CloneAdvisoryRepo clones the advisories repository
func (dvi *defaultVexiImplementation) CloneAdvisoryRepo(opts options.Options) error {
	if _, err := git.CloneOrOpenGitHubRepo(
		opts.AdvisoriesDir, opts.RepoOrg, opts.RepoName, false,
	); err != nil {
		return fmt.Errorf(
			"cloning repository %s/%s to %s: %w",
			opts.RepoOrg, opts.RepoName, opts.AdvisoriesDir, err,
		)
	}
	return nil
}

// DownloadSBOM retrieves all the SBOMs associated with the image.
func (dvi *defaultVexiImplementation) DownloadSBOM(opts options.Options, imageRef string) ([]*payload.Document, error) {
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

// ParseSBOM takes a document discovered by deployer, detects the format and
// returns a protobom with the parsed data.
func (dvi *defaultVexiImplementation) ParseSBOM(payloadDoc *payload.Document) (*sbom.Document, error) {
	r := reader.New()
	bom, err := r.ParseStream(payloadDoc)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	return bom, nil
}

func (dvi *defaultVexiImplementation) FilterSBOMPackages(bom *sbom.Document) (*sbom.NodeList, error) {
	// Fetch all apk nodes from the SBOM
	nodelist := bom.NodeList.GetNodesByPurlType("apk")

	// Assemble a list of all non-wolfi apks
	list := []string{}
	for _, n := range nodelist.Nodes {
		if !strings.HasPrefix(string(n.Purl()), "pkg:apk/wolfi/") {
			list = append(list, n.Id)
		}
	}

	// Remove the nodes
	nodelist.RemoveNodes(list)

	// Return the nodelist
	return nodelist, nil
}

func (dvi *defaultVexiImplementation) FindPackageAdvisories(opts options.Options, nodelist *sbom.NodeList) ([]v2.Document, error) {
	advisoriesFsys := rwos.DirFS(opts.AdvisoriesDir)
	advisoryCfgs, err := v2.NewIndex(advisoriesFsys)
	if err != nil {
		return nil, err
	}

	var cfgs []v2.Document
	for _, node := range nodelist.Nodes {
		cfgs = append(cfgs, advisoryCfgs.Select().WhereName(node.Name).Configurations()...)
	}
	return cfgs, nil
}

func (dvi *defaultVexiImplementation) GenerateVEXData([]v2.Document) ([]*vex.VEX, error) {
	return nil, nil
}
func (dvi *defaultVexiImplementation) MergeDocuments([]*vex.VEX) (*vex.VEX, error) {
	return nil, nil
}
func (dvi *defaultVexiImplementation) WriteVexDocument(*vex.VEX) error {
	return nil
}
