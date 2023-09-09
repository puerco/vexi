package options

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-utils/util"
)

type Options struct {
	Platform           string
	PredicateTypesList string
	AdvisoriesDir      string
	// IsTempDIr takes a bool value that, when true, will cause the advisories dir to be cloned
	IsTempDir bool
	RepoOrg   string
	RepoName  string
}

var Default = Options{
	RepoOrg:  "wolfi-dev",
	RepoName: "advisories",
}

// Validate checks an options set to ensure it is sound. If the advisories
// directory is emtpy, it will create a temporary one to clone the wolfi
// repository into it.
func (opts *Options) Validate() error {
	var dirErr, repoErr, orgErr error
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

	if opts.RepoName == "" {
		repoErr = errors.New("repository name not set")
	}

	if opts.RepoOrg == "" {
		orgErr = errors.New("github organization name not set")
	}
	return errors.Join(
		dirErr, repoErr, orgErr,
	)
}
