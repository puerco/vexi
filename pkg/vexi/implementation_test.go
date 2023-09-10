package vexi

import (
	"testing"

	"github.com/puerco/vexi/pkg/vexi/options"
	"github.com/stretchr/testify/require"
)

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
