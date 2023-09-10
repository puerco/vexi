package convert

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// This package contains functions to convert data from advisories to VEX

// EventToVEXStatus converts an advisory event type to the corresponding
// vex status. Note that EventTypeAnalysisNotPlanned and EventTypeFixNotPlanned
// don't have good equivalentes in VEX so those event types will return an
// empty status.
func EventToVEXStatus(evt v2.Event) vex.Status {
	switch evt.Type {
	case v2.EventTypeFixed:
		return vex.StatusFixed

	case v2.EventTypeDetection:
		return vex.StatusUnderInvestigation

	case v2.EventTypeTruePositiveDetermination:
		return vex.StatusAffected

	case v2.EventTypeFalsePositiveDetermination:
		return vex.StatusNotAffected

		// case v2.EventTypeAnalysisNotPlanned:
	// case v2.EventTypeFixNotPlanned:

	default:
		return ""
	}
}

// PurlFromRef returns a purl capturing the image reference
func PurlFromRef(imageRef string) (string, error) {
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
