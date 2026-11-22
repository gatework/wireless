package cli

import (
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/term"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/internal/workflow"
)

// statusGroups are the dimension groups status reports, in the order an
// operator thinks about them.
var statusGroups = []struct {
	label string
	dims  []evidence.Dimension
}{
	{statusClients, []evidence.Dimension{wireless.DimensionClients}},
	{statusSessions, []evidence.Dimension{wireless.DimensionDot1X, wireless.DimensionMAC}},
	{statusAPs, []evidence.Dimension{wireless.DimensionAccessPoints, wireless.DimensionBSS}},
	{statusConflicts, []evidence.Dimension{wireless.DimensionConflicts, wireless.DimensionBlocked}},
	{statusConfig, []evidence.Dimension{wireless.DimensionConfiguration}},
}

func (a *app) statusCommand() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: shortStatus, Args: cobra.NoArgs, GroupID: groupCache,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := a.config(ctx)
			if err != nil {
				return err
			}
			st, err := cfg.Store()
			if err != nil {
				return err
			}
			captures, err := st.LoadAll(ctx)
			if err != nil {
				return err
			}
			days, _ := cfg.Sightings().Days()
			targets, _ := cfg.Targets(ctx, a.controllers)
			a.printf(statusConfigLine, firstNonEmpty(cfg.Path, statusNoConfig))
			a.printf(statusLoginLine, yesNoWord(cfg.HasCredentials(ctx)), len(targets))
			a.printf(statusCacheLine, cfg.CacheDir, cfg.Cache.Mode, shortDuration(cfg.Cache.Timeout), shortDuration(cfg.Cache.RetryAfter))
			if cfg.Snapshot != "" {
				a.printf(statusSourceLine, cfg.Snapshot)
			}
			if len(days) > 0 {
				a.printf(statusJournalLine, days[0], days[len(days)-1], len(days))
			} else {
				a.printf(statusNoJournal)
			}
			a.watchStatus(ctx, cfg)
			header := []string{statusController}
			for _, g := range statusGroups {
				header = append(header, g.label)
			}
			t := newTable(append(header, statusLastRefresh)...)
			vendor := cfg.Vendor()
			for _, c := range captures {
				host := c.Host.String()
				if !a.selects(host, sysnameOf(c.Prompt)) {
					continue
				}
				row := []string{firstNonEmpty(sysnameOf(c.Prompt), host) + "(" + host + ")"}
				for _, g := range statusGroups {
					row = append(row, a.groupAge(vendor, c, g.dims, cfg.Cache))
				}
				refresh := "-"
				if rs, ok, _ := st.Status(ctx, c.Host); ok {
					refresh = a.age(rs.LastAttempt)
					if rs.Failed() {
						refresh += "（" + term.Chinese().Text(string(rs.Failure)) + "）"
					}
				}
				t.add(append(row, refresh)...)
			}
			return t.render(a.env.Stdout)
		},
	}
}

// groupAge shows the oldest age among dims, marked when past its TTL.
func (a *app) groupAge(v workflow.Vendor, c capture.Capture, dims []evidence.Dimension, p workflow.Policy) string {
	var oldest time.Time
	stale := false
	for _, d := range dims {
		at, ok := workflow.RecordedAt(v, c, d)
		if !ok {
			return "-"
		}
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
		ttl, ok := p.TTL[d]
		if !ok {
			ttl = p.DefaultTTL
		}
		stale = stale || a.env.Now().Sub(at) > ttl
	}
	s := a.age(oldest)
	if stale {
		s += statusStaleMark
	}
	return s
}

func (a *app) cacheCommand() *cobra.Command {
	cache := &cobra.Command{Use: "cache", Short: shortCache, GroupID: groupCache}
	var all bool
	refresh := &cobra.Command{
		Use: "refresh", Short: shortCacheRefresh, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.config(cmd.Context())
			if err != nil {
				return err
			}
			if all {
				cfg.Cache.Mode = workflow.ModeLive
			}
			_, err = a.index(cmd.Context())
			return err
		},
	}
	refresh.Flags().BoolVar(&all, "all", false, flagRefreshAll)
	imp := &cobra.Command{
		Use: "import <离线快照目录>", Short: shortCacheImport, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := a.config(cmd.Context())
			if err != nil {
				return err
			}
			st, err := cfg.Store()
			if err != nil {
				return err
			}
			r, err := st.Import(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			a.printf(msgImportResult, r.Devices, r.Updated, cfg.CacheDir)
			return nil
		},
	}
	prune := &cobra.Command{
		Use: "prune", Short: shortCachePrune, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.config(cmd.Context())
			if err != nil {
				return err
			}
			st, err := cfg.Store()
			if err != nil {
				return err
			}
			n, err := st.Prune(a.env.Now())
			if err != nil {
				return err
			}
			a.printf(msgPruned, n)
			return nil
		},
	}
	cache.AddCommand(refresh, imp, prune)
	return cache
}

func yesNoWord(b bool) string {
	if b {
		return wordConfigured
	}
	return wordMissing
}

// shortDuration prints "2m" rather than "2m0s".
func shortDuration(d time.Duration) string {
	s := d.String()
	for _, zero := range []string{"0s", "0m"} {
		if t := strings.TrimSuffix(s, zero); t != s && t != "" && !strings.HasSuffix(t, ".") {
			s = t
		}
	}
	return s
}
