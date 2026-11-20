package cli

import (
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// Command groups, in the order an operator works.
const (
	groupFind    = "find"
	groupAnalyze = "analyze"
	groupCache   = "cache"
	groupAction  = "action"
)

// usageTemplate is cobra's template with Chinese headings.
const usageTemplate = `用法：{{if .Runnable}}
  {{useLine .UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} <子命令>{{end}}{{if gt (len .Aliases) 0}}

别名：
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

示例：
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

子命令：{{range $cmds}}{{if .IsAvailableCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) .IsAvailableCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

其他：{{range $cmds}}{{if (and (eq .GroupID "") .IsAvailableCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

参数：
{{cleanFlags .LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

全局参数：
{{cleanFlags .InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

运行 "{{.CommandPath}} <子命令> --help" 查看子命令用法。{{end}}
`

// templateFuncs guards the one-time registration of template functions.
var templateFuncs sync.Once

// localize installs the Chinese help on root and its subcommands.
func localize(root *cobra.Command) {
	templateFuncs.Do(func() {
		// cobra keeps template functions in a global map: register once.
		cobra.AddTemplateFunc("cleanFlags", cleanFlags)
		cobra.AddTemplateFunc("useLine", func(s string) string { return strings.ReplaceAll(s, "[flags]", "[参数]") })
	})
	root.AddGroup(
		&cobra.Group{ID: groupFind, Title: titleFind},
		&cobra.Group{ID: groupAnalyze, Title: titleAnalyze},
		&cobra.Group{ID: groupCache, Title: titleCache},
		&cobra.Group{ID: groupAction, Title: titleAction},
	)
	root.SetUsageTemplate(usageTemplate)
	root.SetHelpCommand(&cobra.Command{Use: "help [子命令]", Short: shortHelp, Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _, err := root.Find(args)
			if err != nil || target == nil {
				return root.Help()
			}
			return target.Help()
		}})
	root.CompletionOptions.HiddenDefaultCmd = true
	root.Flags().BoolP("help", "h", false, flagHelp)
	root.Flags().BoolP("version", "v", false, flagVersion)
	root.SetVersionTemplate("wireless {{.Version}}\n")
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("help") == nil {
			c.Flags().BoolP("help", "h", false, flagHelp)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// cleanFlags blanks pflag's "[=true|false]" on boolean flags, keeping the
// width so descriptions stay aligned.
func cleanFlags(s string) string {
	const marker = "[=true|false]"
	return strings.ReplaceAll(s, marker, strings.Repeat(" ", len(marker)))
}

// suggestion returns the subcommand a mistyped first word most likely
// meant, so "wireless fnd x" hints at find instead of searching "fnd x".
func suggestion(root *cobra.Command, word string) string {
	if len(word) < 2 || strings.ContainsAny(word, ".:-/*") {
		return ""
	}
	if root.SuggestionsMinimumDistance <= 0 {
		root.SuggestionsMinimumDistance = 2
	}
	for _, s := range root.SuggestionsFor(word) {
		return s
	}
	return ""
}
