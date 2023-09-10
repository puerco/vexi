package cli

import (
	"fmt"

	"github.com/puerco/vexi/pkg/vexi"
	"github.com/spf13/cobra"
)

func addGenerate(parent *cobra.Command) {
	generateCmd := &cobra.Command{
		Use:     "generate",
		Short:   "gen",
		Long:    "generate inspects a container image generates VEX data from its packages",
		Example: "vexi generate cgr.dev/chainguard/node",
		// ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {},
		//Args: func(cmd *cobra.Command, args []string) error {},
		//BashCompletionFunction: "",
		Deprecated:  "",
		Annotations: map[string]string{},
		RunE: func(cmd *cobra.Command, args []string) error {
			generator := vexi.NewGenerator()
			err := generator.ImageVEX("cgr.dev/chainguard/curl@sha256:fa5292b1973e8a6b57fd9e7809526d7484dc37749ecff1402e6493d797ed3e24")
			if err != nil {
				return fmt.Errorf("generating VEX data: %w", err)
			}
			return nil

		},

		FParseErrWhitelist:         cobra.FParseErrWhitelist{},
		CompletionOptions:          cobra.CompletionOptions{},
		TraverseChildren:           false,
		Hidden:                     false,
		SilenceErrors:              false,
		SilenceUsage:               false,
		DisableFlagParsing:         false,
		DisableAutoGenTag:          false,
		DisableFlagsInUseLine:      false,
		DisableSuggestions:         false,
		SuggestionsMinimumDistance: 0,
	}
	parent.AddCommand(generateCmd)
}
