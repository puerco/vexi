package options

import (
	"errors"
	"fmt"
	"os"

	"github.com/puerco/deployer/pkg/payload"
	"github.com/puerco/vexi/pkg/convert"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
	PredicateTypesList []string

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

	// Slug
	repoSlug string
}

// PredicateTypeFormats returns simple text labels that represent the SBOM types
// that are more suitable to use in flags.
func (opts *Options) PredicateTypeFormats() []payload.Format {
	ret := []payload.Format{}
	for _, pt := range opts.PredicateTypesList {
		switch pt {
		case "spdx":
			ret = append(ret, payload.Format("text/spdx"))
		case "cyclonedx":
			ret = append(ret, payload.Format("application/vnd.cyclonedx"))
		default:
			ret = append(ret, payload.Format(pt))
		}
	}
	return ret
}

var Default = Options{
	RepoOrg:  "wolfi-dev",
	RepoName: "advisories",
	PredicateTypesList: []string{
		"spdx", "cyclonedx",
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

// AddGenerateOptions
func (opts *Options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&opts.PredicateTypesList, "predicates", "p", Default.PredicateTypesList,
		"list of predicate types to download from registry",
	)

	cmd.PersistentFlags().StringVarP(
		&opts.repoSlug, "repository", "r", fmt.Sprintf("%s/%s", Default.RepoOrg, Default.RepoName),
		"repository slug where the advisories are stored",
	)

	cmd.PersistentFlags().StringVarP(
		&opts.AdvisoriesDir, "advisories", "a", Default.AdvisoriesDir,
		"directory holding the advisories (prevents cloning the advisory repository)",
	)

	cmd.PersistentFlags().StringVarP(
		&opts.OutFile, "file", "f", "",
		"file to write the resulting OpenVEX document, defaults to STDOUT",
	)
}
