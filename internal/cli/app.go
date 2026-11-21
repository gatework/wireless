package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/internal/bootstrap"
	"github.com/gatework/wireless/internal/workflow"
)

// Version is the release of the command.
const Version = "0.2.0"

// Exit codes.
const (
	ExitOK          = 0
	ExitIncomplete  = 1
	ExitError       = 2
	ExitInterrupted = 130
)

// errNotFound marks a query that matched nothing; it exits 1.
var errNotFound = errors.New("cli: not found")

// Env is the process context the command runs in.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Environ        []string
	Home           string
	// Interactive reports whether stdin is a terminal.
	Interactive bool
	Now         func() time.Time
}

// app holds global flags and lazily built resources for one invocation.
type app struct {
	env         Env
	configPath  string
	envPath     string
	snapshot    string
	json        bool
	live        bool
	offline     bool
	cacheDir    string
	limit       int
	verbose     bool
	controllers []string
	cfg         *bootstrap.Config
	// fresh is the freshness of the last loaded index, reported with
	// every JSON result.
	fresh *workflow.Freshness
}

// Run executes the command line and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	a := &app{env: env}
	root := a.root() //nolint:contextcheck // cobra hands ctx to every command through cmd.Context()
	root.SetArgs(args)
	root.SetIn(env.Stdin)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return ExitOK
	case ctx.Err() != nil || errors.Is(err, context.Canceled):
		return ExitInterrupted
	case errors.Is(err, errNotFound), errors.Is(err, bootstrap.ErrNoTargets), errors.Is(err, errIncomplete), errors.Is(err, errAborted):
		return ExitIncomplete
	default:
		fmt.Fprintln(env.Stderr, errText(err))
		return ExitError
	}
}

func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use: "wireless [IP|MAC|账号|AP名]", Short: shortRoot, Long: longRoot,
		SilenceUsage: true, SilenceErrors: true, Version: Version,
		// Anything that is not a subcommand is a lookup: the most common
		// question needs no command to remember.
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			err := a.lookup(cmd.Context(), strings.Join(args, " "))
			if errors.Is(err, errNotFound) && len(args) > 1 {
				if s := suggestion(cmd, args[0]); s != "" {
					fmt.Fprintf(a.env.Stderr, msgDidYouMean, args[0], s, strings.Join(args[1:], " "))
				}
			}
			return err
		},
	}
	f := root.PersistentFlags()
	f.StringVar(&a.configPath, "config", "", flagConfig)
	f.StringVar(&a.envPath, "env-file", "", flagEnvFile)
	f.StringVar(&a.snapshot, "snapshot", "", flagSnapshot)
	f.BoolVar(&a.json, "json", false, flagJSON)
	f.BoolVar(&a.live, "live", false, flagLive)
	f.BoolVar(&a.offline, "offline", false, flagOffline)
	f.StringVar(&a.cacheDir, "cache", "", flagCache)
	f.IntVar(&a.limit, "limit", defaultLimit, flagLimit)
	f.BoolVar(&a.verbose, "verbose", false, flagVerbose)
	f.StringArrayVarP(&a.controllers, "controller", "c", nil, flagController)
	root.AddCommand(
		a.collectCommand(), a.findCommand(), a.clientCommand(), a.apCommand(), a.authCommand(),
		a.conflictsCommand(), a.summaryCommand(), a.healthCommand(), a.kickCommand(), a.blockCommand(),
		a.rfCommand(), a.roamCommand(), a.watchCommand(), a.statusCommand(), a.cacheCommand(),
	)
	groups := map[string]string{
		"find": groupFind, "client": groupFind, "ap": groupFind, "auth": groupFind, "conflicts": groupFind,
		"summary": groupAnalyze, "health": groupAnalyze, "rf": groupAnalyze, "roam": groupAnalyze,
		"collect": groupCache, "watch": groupCache,
		"kick": groupAction, "block": groupAction,
	}
	for _, c := range root.Commands() {
		if g, ok := groups[c.Name()]; ok {
			c.GroupID = g
		}
	}
	localize(root)
	return root
}

// lookup answers a bare query: one associated station gets its full
// panel, several get a table, nothing gets a hint.
func (a *app) lookup(ctx context.Context, text string) error {
	q, err := wireless.ParseQuery(text)
	if err != nil {
		return err
	}
	ix, err := a.index(ctx, clientDimensions...)
	if err != nil {
		return err
	}
	r := ix.Find(q)
	if len(r.Clients) == 1 && !a.json {
		return a.showClients(ctx, ix, r.Clients, defaultSince)
	}
	if a.json {
		return a.emitJSON(r)
	}
	if r.Empty() {
		a.printf(msgNotFound, q.String())
		a.printf(msgLookupHint)
		return errNotFound
	}
	return a.renderResult(r)
}

func (a *app) config(ctx context.Context) (*bootstrap.Config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	cfg, err := bootstrap.Load(ctx, bootstrap.Options{
		ConfigPath: a.configPath, EnvPath: a.envPath, Environ: a.env.Environ, Home: a.env.Home,
	})
	if err != nil {
		return nil, err
	}
	if a.snapshot != "" {
		cfg.Snapshot = a.snapshot
	}
	if a.cacheDir != "" {
		cfg.CacheDir = a.cacheDir
	}
	switch {
	case a.offline:
		cfg.Cache.Mode = workflow.ModeOffline
	case a.live:
		cfg.Cache.Mode = workflow.ModeLive
	}
	a.cfg = cfg
	return cfg, nil
}

// selects applies --controller to a controller.
func (a *app) selects(host, name string) bool {
	if len(a.controllers) == 0 {
		return true
	}
	addr, _ := netip.ParseAddr(host)
	return slices.ContainsFunc(a.controllers, func(s string) bool {
		if p, err := netip.ParsePrefix(s); err == nil {
			return p.Contains(addr)
		}
		if b, err := netip.ParseAddr(s); err == nil {
			return addr == b
		}
		return strings.Contains(strings.ToLower(name), strings.ToLower(s))
	})
}

// emitJSON writes {"freshness": ..., "result": v}. Freshness is present
// whenever the result was computed from the cache.
func (a *app) emitJSON(v any) error {
	enc := json.NewEncoder(a.env.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	doc := struct {
		Freshness *workflow.Freshness `json:"freshness,omitempty"`
		Result    any                 `json:"result"`
	}{a.fresh, v}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("cli: %w", err)
	}
	return nil
}

func (a *app) printf(format string, args ...any) {
	fmt.Fprintf(a.env.Stdout, format, safeArgs(args)...)
}

func sysnameOf(prompt string) string { return strings.Trim(strings.TrimSpace(prompt), "<>[]") }

// errText words an error for the operator. Known conditions get a plain
// explanation; anything else keeps its detail after a Chinese prefix.
func errText(err error) string {
	switch {
	case errors.Is(err, wireless.ErrEmptyQuery):
		return errEmptyQuery
	case errors.Is(err, wireless.ErrInvalidMAC):
		return errInvalidMAC
	case errors.Is(err, bootstrap.ErrCredentials):
		return errNoLogin
	case errors.Is(err, bootstrap.ErrConfig):
		return errConfigPrefix + err.Error()
	case strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "unknown shorthand") ||
		strings.Contains(err.Error(), "invalid argument") || strings.Contains(err.Error(), "accepts "):
		return errUsagePrefix + err.Error() + errUsageHint
	}
	return errPrefix + err.Error()
}
