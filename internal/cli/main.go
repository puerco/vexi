package cli

import (
	"github.com/spf13/cobra"
)

func Execute() error {
	rootCmd := cobra.Command{}

	addGenerate(&rootCmd)

	if err := rootCmd.Execute(); err != nil {
		return err
	}
	return nil
}
