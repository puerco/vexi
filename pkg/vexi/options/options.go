package options

import (
	"errors"
	"fmt"
	"os"

	"github.com/puerco/deployer/pkg/payload"
	"github.com/puerco/vexi/pkg/convert"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-utils/util"
)

type Options struct {
	// Reference of the container image to VEX. If the reference points to a
	// multiarch index fronting more than one image, Platform must be specified.
	ImageReference string

	// Image purl is a package URL rendering of the image reference
	ImagePurl string

	// Platform is a platform label. If the image reference is a multiarch index
	// this will be used to select one of images fronted by the index.
	Platform string

	// PredicateTypesList List of predicates to consider when fetching attached documents
	// from the registry. By default, vexi will look for SPDX/CycloneDX documents only.
	PredicateTypesList []payload.Format

	// Directory to look for advisory data. If left blank, the repository will
	// be cloned to a temporary directory.
	AdvisoriesDir string

	// IsTempDIr takes a bool value that, when true, will cause the advisories dir to be cloned
	IsTempDir bool

	// RepoOrg is the github organization of the advisory repository
	RepoOrg string

	// RepoName is the advisory repository name
	RepoName string

	// Outfile is the path to a file to sotre the resulting OpenVEX document.
	// is left blank, it will be output to STDOUT.
	OutFile string
}

var Default = Options{
	RepoOrg:  "wolfi-dev",
	RepoName: "advisories",
	PredicateTypesList: []payload.Format{
		payload.Format("text/spdx"),
		payload.Format("application/vnd.cyclonedx"),
	},
}

// Validate checks an options set to ensure it is sound. If the advisories
// directory is emtpy, it will create a temporary one to clone the wolfi
// repository into it.
func (opts *Options) Validate() error {
	var dirErr, repoErr, orgErr, purlErr error
	if opts.AdvisoriesDir == "" {
		tmp, err := os.MkdirTemp("", "vexi-advisories-")
		if err != nil {
			dirErr = fmt.Errorf("creating temporary advisories dir: %w", err)
		}
		os.Remove(tmp)
		opts.AdvisoriesDir = tmp
		opts.IsTempDir = true
		logrus.Debugf("advisories will be cloned to %s", tmp)
	} else {
		if !util.Exists(opts.AdvisoriesDir) {
			dirErr = fmt.Errorf("advisories directory %s not found", opts.AdvisoriesDir)
		}
	}

	// Generate and store the image purl equivalent
	purlString, purlErr := convert.PurlFromRef(opts.ImageReference)
	opts.ImagePurl = purlString

	if opts.RepoName == "" {
		repoErr = errors.New("repository name not set")
	}

	if opts.RepoOrg == "" {
		orgErr = errors.New("github organization name not set")
	}
	return errors.Join(
		dirErr, repoErr, orgErr, purlErr,
	)
}
