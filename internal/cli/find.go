package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/set"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/conflict"
)

func (a *app) findCommand() *cobra.Command {
	return &cobra.Command{
		Use: "find <IP|网段|MAC|MAC片段|账号|AP名>", Short: shortFind, Args: cobra.ExactArgs(1),
		Example: "  wireless find 10.158.152.184\n  wireless find d5c7\n  wireless find 10.158.8.0/24\n  wireless find 18620346\n  wireless find 6FAP06",
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := wireless.ParseQuery(args[0])
			if err != nil {
				return err
			}
			ix, err := a.index(cmd.Context(), wireless.DimensionClients, wireless.DimensionDot1X, wireless.DimensionMAC)
			if err != nil {
				return err
			}
			r := ix.Find(q)
			if a.json {
				return a.emitJSON(r)
			}
			if r.Empty() {
				a.printf(msgNotFound, q.String())
				return errNotFound
			}
			return a.renderResult(r)
		},
	}
}

func (a *app) renderResult(r wireless.Result) error {
	sections := []struct {
		title string
		n     int
		t     *table
	}{
		{msgSectionClients, len(r.Clients), clientsTable(r.Clients)},
		{msgSectionOrphans, len(r.Sessions), sessionsTable(r.Sessions)},
		{msgSectionAPs, len(r.APs), apsTable(r.APs)},
		{msgSectionConfl, len(groupConflicts(r.Conflicts)), conflictsTable(groupConflicts(r.Conflicts))},
		{msgSectionBlocked, len(r.Blocked), blockedTable(r.Blocked)},
	}
	first := true
	for _, s := range sections {
		if s.n == 0 {
			continue
		}
		if !first {
			a.printf("\n")
		}
		first = false
		a.printf(s.title, s.n)
		if err := a.list(s.t); err != nil {
			return err
		}
	}
	return nil
}

func clientsTable(views []wireless.ClientView) *table {
	t := newTable(headFindClients...)
	for _, v := range views {
		c := v.Client
		t.add(v.Controller.Label(), c.APName, fmt.Sprintf("R%d/%s ch%d", c.RadioID, c.Band(), c.Channel), c.SSID,
			intCell(c.VLAN), addrCell(c.IPv4), macCell(c.MAC), dash(username(v)), dash(v.Access.String()),
			intCell(c.RSSI), durationCell(c.Online))
	}
	return t
}

func sessionsTable(views []wireless.SessionView) *table {
	t := newTable(headSessions...)
	for _, v := range views {
		s := v.Session
		t.add(v.Controller.Label(), s.Kind.String(), macCell(s.MAC), dash(s.Username), dash(s.Domain), dash(s.Method),
			addrCell(s.IPv4), dash(s.APName), dash(s.SSID), intCell(s.AuthorizedVLAN), durationCell(s.Online))
	}
	return t
}

func apsTable(views []wireless.APView) *table {
	t := newTable(headAPs...)
	for _, v := range views {
		ap := v.AP
		t.add(v.Controller.Label(), ap.Name, dash(string(ap.State)), dash(ap.Model), addrCell(ap.IP), macCell(ap.MAC),
			fmt.Sprint(v.Clients), durationCell(ap.Online), dash(ap.Software))
	}
	return t
}

func blockedTable(views []wireless.BlockedView) *table {
	t := newTable(headBlocked...)
	for _, v := range views {
		t.add(v.Controller.Label(), macCell(v.Entry.MAC), v.Entry.Source, dash(v.Entry.Detail))
	}
	return t
}

// conflictGroup aggregates the conflict history of one IP on one
// controller.
type conflictGroup struct {
	Controller wireless.Controller `json:"controller"`
	IP         string              `json:"ip"`
	Count      int                 `json:"count"`
	Latest     time.Time           `json:"latest"`
	MACs       []wireless.MAC      `json:"macs"`
}

func groupConflicts(views []wireless.ConflictView) []conflictGroup {
	type key struct{ host, ip string }
	index := map[key]int{}
	var out []conflictGroup
	for _, v := range views {
		k := key{v.Controller.Host, v.Conflict.IP.String()}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, conflictGroup{Controller: v.Controller, IP: k.ip})
		}
		g := &out[i]
		g.Count++
		if v.Conflict.At.After(g.Latest) {
			g.Latest = v.Conflict.At
		}
		for _, m := range []wireless.MAC{v.Conflict.NewMAC, v.Conflict.OldMAC} {
			if !slices.Contains(g.MACs, m) {
				g.MACs = append(g.MACs, m)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b conflictGroup) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), b.Latest.Compare(a.Latest))
	})
	return out
}

func conflictsTable(groups []conflictGroup) *table {
	t := newTable(headConflicts...)
	for _, g := range groups {
		macs := make([]string, len(g.MACs))
		for i, m := range g.MACs {
			macs[i] = m.H3C()
		}
		t.add(g.Controller.Label(), g.IP, fmt.Sprint(g.Count), timeCell(g.Latest), strings.Join(macs, " "))
	}
	return t
}

func (a *app) conflictsCommand() *cobra.Command {
	var ip string
	var days int
	cmd := &cobra.Command{
		Use: "conflicts", Short: shortConflicts, Args: cobra.NoArgs,
		Example: "  wireless conflicts --days 7\n  wireless conflicts --ip 10.158.0.0/16",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ix, err := a.index(cmd.Context(), wireless.DimensionConflicts, wireless.DimensionClients)
			if err != nil {
				return err
			}
			var q *wireless.Query
			if ip != "" {
				parsed, err := wireless.ParseQuery(ip)
				if err != nil {
					return err
				}
				q = &parsed
			}
			var groups []conflict.Group
			for _, s := range ix.Snapshots() {
				var since time.Time
				if days > 0 {
					since = s.CollectedAt.AddDate(0, 0, -days)
				}
				for _, g := range conflict.Analyze(s, since) {
					if q == nil || q.MatchAddr(g.IP) {
						groups = append(groups, g)
					}
				}
			}
			slices.SortStableFunc(groups, func(x, y conflict.Group) int { return cmp.Compare(y.Count, x.Count) })
			if a.json {
				return a.emitJSON(groups)
			}
			if len(groups) == 0 {
				a.printf(msgNotFound, ip)
				return errNotFound
			}
			return a.renderConflicts(groups)
		},
	}
	cmd.Flags().StringVar(&ip, "ip", "", flagIP)
	cmd.Flags().IntVar(&days, "days", 0, flagDays)
	return cmd
}

// renderConflicts shows a per-pattern summary with advice, then the
// addresses, most frequent first.
func (a *app) renderConflicts(groups []conflict.Group) error {
	counts := map[conflict.Pattern]int{}
	for _, g := range groups {
		counts[g.Pattern]++
	}
	a.printf(msgSectionConfl, len(groups))
	for _, p := range []conflict.Pattern{conflict.PatternShared, conflict.PatternPair, conflict.PatternSporadic} {
		if counts[p] > 0 {
			a.printf(msgConflictPattern, p.Word(), counts[p], p.Advice())
		}
	}
	a.printf("\n")
	t := newTable(headConflictGroups...)
	for _, g := range groups {
		var notes []string
		if g.Foreign {
			notes = append(notes, noteForeign)
		}
		for _, b := range g.Batches {
			notes = append(notes, fmt.Sprintf(noteBatch, b.OUI, b.Count))
		}
		macs := make([]string, 0, min(len(g.MACs), 3))
		for _, m := range g.MACs[:min(len(g.MACs), 3)] {
			macs = append(macs, m.H3C())
		}
		if len(g.MACs) > 3 {
			macs = append(macs, fmt.Sprintf("…+%d", len(g.MACs)-3))
		}
		t.add(g.Controller.Label(), g.IP.String(), fmt.Sprint(g.Count), timeCell(g.Latest), g.Pattern.Word(),
			strings.Join(macs, " "), dash(strings.Join(notes, "；")))
	}
	return a.list(t)
}

func (a *app) authCommand() *cobra.Command {
	var method, user, ssid, vlans string
	cmd := &cobra.Command{
		Use: "auth", Short: shortAuth, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			vlanSet, err := set.Parse[uint16](vlans)
			if err != nil {
				return fmt.Errorf("cli: --vlan: %w", err)
			}
			ix, err := a.index(cmd.Context(), wireless.DimensionDot1X, wireless.DimensionMAC)
			if err != nil {
				return err
			}
			filter := sessionFilter{method: method, user: strings.ToLower(user), ssid: ssid, vlans: vlanSet}
			var views []wireless.SessionView
			for _, s := range ix.Snapshots() {
				for _, list := range [][]wireless.AuthSession{s.Dot1X.Facts, s.MAC.Facts} {
					for i := range list {
						if filter.match(&list[i]) {
							views = append(views, wireless.SessionView{Controller: s.Controller, Session: &list[i]})
						}
					}
				}
			}
			if a.json {
				return a.emitJSON(views)
			}
			if len(views) == 0 {
				a.printf(msgNotFound, strings.TrimSpace(method+" "+user+" "+ssid+" "+vlans))
				return errNotFound
			}
			if err := a.list(sessionsTable(views)); err != nil {
				return err
			}
			a.printf("\n" + msgStatsTitle)
			return sessionStats(views).render(a.env.Stdout)
		},
	}
	f := cmd.Flags()
	f.StringVar(&method, "method", "", flagMethod)
	f.StringVar(&user, "user", "", flagUser)
	f.StringVar(&ssid, "ssid", "", flagSSID)
	f.StringVar(&vlans, "vlan", "", flagVLAN)
	return cmd
}

// sessionFilter selects authentication sessions; zero fields match all.
type sessionFilter struct {
	method, user, ssid string
	vlans              *set.Set[uint16]
}

func (f sessionFilter) match(s *wireless.AuthSession) bool {
	return (f.method == "" || string(s.Kind) == f.method) &&
		(f.user == "" || strings.Contains(strings.ToLower(s.Username), f.user)) &&
		(f.ssid == "" || s.SSID == f.ssid) &&
		(f.vlans.IsEmpty() || s.AuthorizedVLAN > 0 && s.AuthorizedVLAN <= 4094 && f.vlans.Contains(uint16(s.AuthorizedVLAN)))
}

// sessionStats counts sessions by authenticator, domain and authorized
// VLAN, most frequent first.
func sessionStats(views []wireless.SessionView) *table {
	type key struct{ dim, value string }
	counts := map[key]int{}
	for _, v := range views {
		s := v.Session
		counts[key{"type", s.Kind.String()}]++
		counts[key{"domain", dash(s.Domain)}]++
		counts[key{"vlan", intCell(s.AuthorizedVLAN)}]++
		counts[key{"ssid", dash(s.SSID)}]++
	}
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	order := []string{"type", "ssid", "domain", "vlan"}
	slices.SortFunc(keys, func(a, b key) int {
		return cmp.Or(cmp.Compare(slices.Index(order, a.dim), slices.Index(order, b.dim)), cmp.Compare(counts[b], counts[a]), cmp.Compare(a.value, b.value))
	})
	t := newTable(headStats...)
	shown := map[string]int{}
	for _, k := range keys {
		if shown[k.dim]++; shown[k.dim] > statsPerDimension {
			continue
		}
		t.add(statsWords[k.dim], k.value, fmt.Sprint(counts[k]))
	}
	return t
}

// statsPerDimension bounds each statistics dimension to its top values.
const statsPerDimension = 10

func username(v wireless.ClientView) string {
	if s, ok := v.Session(); ok && s.Username != "" {
		return s.Username
	}
	return v.Client.Username
}
