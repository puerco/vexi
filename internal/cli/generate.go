package cli

import (
	"fmt"

	"github.com/puerco/vexi/pkg/vexi"
	"github.com/puerco/vexi/pkg/vexi/options"
	"github.com/spf13/cobra"
)

func addGenerate(parent *cobra.Command) {
	opts := options.Default
	generateCmd := &cobra.Command{
		Use:   "generate [flags] image_reference",
		Short: "vexi generate [flags] image_reference",
		Long: `vexi generate: distill VEX data from a container image SBOM.

The generate subcommand generates an OpenVEX document from the Wolfi security
information associated to a container image.


When run, VEXi will interact with an image and generate VEX data by performing
these steps:

  1. Look for an attached SBOM in the registry.
  2. Parse the SBOM and extract data about installed Wolfi packages.
  3. Look up any security advisories for each of the packages.
  4. Compose a new OpenVEX document from the advisory data.
  
Advisory data can be read from a directory containing the data files. By default,
VEXi will clone the wolfi-dev/advisories github repository on every run.
  `,
		Example: "vexi generate cgr.dev/chainguard/node@sha256:3afbc808e0fe2af41f9183915f19d843c6b7e9ae3aa321f4bd9bbc1145172927",
		// ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {},
		//Args: func(cmd *cobra.Command, args []string) error {},
		Deprecated:  "",
		Annotations: map[string]string{},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no image reference specified")
			}
			generator := vexi.NewGenerator()
			generator.Options = opts
			// cgr.dev/chainguard/curl@sha256:fa5292b1973e8a6b57fd9e7809526d7484dc37749ecff1402e6493d797ed3e24
			if err := generator.ImageVEX(args[0]); err != nil {
				return fmt.Errorf("generating VEX data: %w", err)
			}
			return nil
		},
		TraverseChildren: false,
		SilenceErrors:    true,
		SilenceUsage:     false,
	}
	opts.AddFlags(generateCmd)
	parent.AddCommand(generateCmd)
}
