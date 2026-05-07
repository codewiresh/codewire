package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	outputFormatText = "text"
	outputFormatJSON = "json"
)

func addOutputFlag(cmd *cobra.Command, output *string, description string) {
	cmd.Flags().StringVarP(output, "output", "o", outputFormatText, description)
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{outputFormatText, outputFormatJSON}, cobra.ShellCompDirectiveNoFileComp
	})
}

func normalizeOutputFormat(raw string) (string, error) {
	switch format := strings.ToLower(strings.TrimSpace(raw)); format {
	case "", outputFormatText:
		return outputFormatText, nil
	case outputFormatJSON:
		return outputFormatJSON, nil
	default:
		return "", fmt.Errorf("unsupported output format %q (expected text or json)", raw)
	}
}

func wantsJSON(raw string) (bool, error) {
	format, err := normalizeOutputFormat(raw)
	if err != nil {
		return false, err
	}
	return format == outputFormatJSON, nil
}
