package vexi

import (
	"testing"

	"github.com/puerco/vexi/pkg/vexi/options"
	"github.com/stretchr/testify/require"
)

func TestPurlFromRef(t *testing.T) {
	for m, tc := range map[string]struct {
		refString string
		expected  string
		mustErr   bool
	}{
		"digest": {
			"nginx@sha256:6926dd802f40e5e7257fded83e0d8030039642e4e10c4a98a6478e9c6fe06153",
			"pkg:oci/nginx@sha256%3A6926dd802f40e5e7257fded83e0d8030039642e4e10c4a98a6478e9c6fe06153",
			false,
		},
		"digest-with-registry": {
			"cgr.dev/chainguard/nginx@sha256:6fc88127201c4338e2278501a52714abb1dedbb664f936eee0927488df5545b3",
			"pkg:oci/nginx@sha256%3A6fc88127201c4338e2278501a52714abb1dedbb664f936eee0927488df5545b3?repository_url=cgr.dev%2Fchainguard",
			false,
		},
		"with-registry": {
			"cgr.dev/chainguard/curl",
			"pkg:oci/curl?repository_url=cgr.dev%2Fchainguard",
			false,
		},
		"with-registry-and-tag": {
			"cgr.dev/chainguard/curl:latest",
			"pkg:oci/curl?repository_url=cgr.dev%2Fchainguard&tag=latest",
			false,
		},
		"default-registry": {
			"alpine",
			"pkg:oci/alpine",
			false,
		},
		"default-registry-explicit": {
			"index.docker.io/library/alpine",
			"pkg:oci/alpine?repository_url=index.docker.io%2Flibrary",
			false,
		},
	} {
		res, err := purlFromRef(tc.refString)
		if tc.mustErr {
			require.Error(t, err, m)
			continue
		}
		require.Equal(t, tc.expected, res, m)
	}
}

func TestReadAdvisories(t *testing.T) {
	opts := options.Options{
		AdvisoriesDir: "testdata/",
	}

	for n, tc := range map[string]struct {
		packageList  []string
		expectedDocs int
		mustErr      bool
	}{
		"single-package": {[]string{"openssl"}, 1, false},
		"two-packages":   {[]string{"openssl", "php"}, 2, false},
		"1-known-1-not":  {[]string{"openssl", "nginx"}, 1, false},
		"none-known":     {[]string{"vexi", "nginx"}, 0, false},
	} {
		res, err := readAdvisories(opts, tc.packageList)
		if tc.mustErr {
			require.Error(t, err, n)
			continue
		}
		require.NoErrorf(t, err, "reading advisories for %s", "openssl")
		require.Equal(t, tc.expectedDocs, len(res))
	}
}
