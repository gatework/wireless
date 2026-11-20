package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/roam"
)

func (a *app) roamCommand() *cobra.Command {
	var since time.Duration
	var top int
	cmd := &cobra.Command{
		Use: "roam [MAC|IP|账号]", Short: shortRoam, Args: cobra.MaximumNArgs(1),
		Example: "  wireless roam                     # 全网乒乓与粘滞 Top N\n  wireless roam aa32-ed65-d5c7 --since 2h\n  wireless roam aa32-ed65-d5c7 --live   # 读取 AC 自身的漫游记录",
		RunE: func(cmd *cobra.Command, args []string) error {
			ix, err := a.index(cmd.Context(), wireless.DimensionClients, wireless.DimensionAccessPoints, wireless.DimensionConfiguration)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				return a.roamStation(cmd, ix, args[0], since)
			}
			return a.roamFleet(cmd, ix, since, top)
		},
	}
	cmd.Flags().DurationVar(&since, "since", defaultSince, flagSince)
	cmd.Flags().IntVar(&top, "top", 20, flagTop)
	return cmd
}

// stickyRow is one suspected sticky station.
type stickyRow struct {
	Controller wireless.Controller `json:"controller"`
	MAC        wireless.MAC        `json:"mac"`
	AP         string              `json:"ap"`
	RSSI       int                 `json:"rssi"`
	Sticky     roam.Sticky         `json:"sticky"`
}

func (a *app) roamFleet(cmd *cobra.Command, ix *wireless.Index, since time.Duration, top int) error {
	cfg, err := a.config(cmd.Context())
	if err != nil {
		return err
	}
	tracks, err := a.tracks(cmd.Context(), since, nil)
	if err != nil {
		return err
	}
	bouncing := slices.DeleteFunc(slices.Clone(tracks), func(t roam.Track) bool { return t.PingPong == nil })
	var sticky []stickyRow
	for v := range ix.Clients() {
		if st := cfg.Models.Roaming.Sticky(ix, &v); st.Suspected {
			sticky = append(sticky, stickyRow{Controller: v.Controller, MAC: v.Client.MAC, AP: v.Client.APName, RSSI: v.Client.RSSI, Sticky: st})
		}
	}
	slices.SortStableFunc(sticky, func(a, b stickyRow) int {
		return cmp.Or(cmp.Compare(b.Sticky.Confidence, a.Sticky.Confidence), cmp.Compare(a.RSSI, b.RSSI))
	})
	if a.json {
		return a.emitJSON(map[string]any{"ping_pong": bouncing, "sticky": sticky, "history": tracks != nil})
	}
	if tracks == nil {
		a.printf(msgNoHistory)
	} else {
		a.printf(msgRoamPingPong, len(bouncing), len(tracks), durationCell(since))
		t := newTable(headPingPong...)
		for _, tr := range bouncing[:min(top, len(bouncing))] {
			pp := tr.PingPong
			t.add(macCell(tr.MAC), tr.Host, strings.Join(pp.APs, "↔"), fmt.Sprint(pp.Bounces), durationCell(pp.Fastest),
				yesNo(pp.SameChannel), yesNo(pp.Edge))
		}
		if err := t.render(a.env.Stdout); err != nil {
			return err
		}
		a.printf("\n")
	}
	a.printf(msgRoamSticky, len(sticky))
	t := newTable(headSticky...)
	for _, s := range sticky[:min(top, len(sticky))] {
		t.add(macCell(s.MAC), s.Controller.Label(), s.AP, fmt.Sprint(s.RSSI), s.Sticky.Confidence.Word(), reasonsText(s.Sticky.Reasons))
	}
	return t.render(a.env.Stdout)
}

func (a *app) roamStation(cmd *cobra.Command, ix *wireless.Index, text string, since time.Duration) error {
	q, err := wireless.ParseQuery(text)
	if err != nil {
		return err
	}
	targets := wireless.Actionable(ix.Resolve(q))
	if len(targets) == 0 {
		a.printf(msgNotFound, text)
		return errNotFound
	}
	var tracks []roam.Track
	for _, tg := range targets {
		v := &wireless.ClientView{Client: &wireless.Client{MAC: tg.MAC}}
		if len(tg.Online) > 0 {
			v.Controller = tg.Online[0]
		}
		if t := a.trackOf(cmd.Context(), v, since); t != nil {
			tracks = append(tracks, *t)
		}
	}
	if a.json {
		return a.emitJSON(tracks)
	}
	if len(tracks) == 0 {
		a.printf(msgNoTrack, text)
		return errNotFound
	}
	for _, tr := range tracks {
		a.printf(msgTrackTitle, tr.MAC.H3C(), tr.Sightings, durationCell(tr.Span), len(tr.Events))
		if pp := tr.PingPong; pp != nil {
			a.printf(msgTrackPingPong, strings.Join(pp.APs, "↔"), pp.Bounces, durationCell(pp.Fastest))
		}
		if tr.Insufficient {
			a.printf(msgTrackSparse)
		}
		t := newTable(headTimeline...)
		for _, e := range tr.Events {
			t.add(timeCell(e.At), eventWords[e.Kind], e.From.Host+"/"+e.From.AP, e.To.Host+"/"+e.To.AP,
				fmt.Sprintf("%s→%s", intCell(e.From.Channel), intCell(e.To.Channel)), fmt.Sprintf("%s→%s", intCell(e.From.RSSI), intCell(e.To.RSSI)))
		}
		if err := t.render(a.env.Stdout); err != nil {
			return err
		}
	}
	return nil
}

func reasonsText(reasons []roam.Reason) string {
	words := make([]string, 0, len(reasons))
	for _, r := range reasons {
		words = append(words, r.Word())
	}
	return strings.Join(words, "；")
}

func yesNo(b bool) string {
	if b {
		return wordYes
	}
	return "-"
}
