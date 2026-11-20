package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/diagnose"
	"github.com/gatework/wireless/quality"
)

// clientDimensions are what a station panel needs.
var clientDimensions = []evidence.Dimension{
	wireless.DimensionClients, wireless.DimensionDot1X, wireless.DimensionMAC,
	wireless.DimensionAccessPoints, wireless.DimensionConflicts, wireless.DimensionBlocked,
}

// clientReport is the JSON form of one station panel.
type clientReport struct {
	View      wireless.ClientView `json:"view"`
	AP        string              `json:"ap"`
	Diagnosis diagnose.Report     `json:"diagnosis"`
}

func (a *app) clientCommand() *cobra.Command {
	var since time.Duration
	cmd := &cobra.Command{
		Use: "client <MAC|IP|账号>", Short: shortClient, Args: cobra.ExactArgs(1),
		Example: "  wireless client aa32-ed65-d5c7\n  wireless client 10.158.8.247 --live",
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := wireless.ParseQuery(args[0])
			if err != nil {
				return err
			}
			ix, err := a.index(cmd.Context(), clientDimensions...)
			if err != nil {
				return err
			}
			r := ix.Find(q)
			if len(r.Clients) == 0 {
				return a.noClient(q, r)
			}
			return a.showClients(cmd.Context(), ix, r.Clients, since)
		},
	}
	cmd.Flags().DurationVar(&since, "since", defaultSince, flagSince)
	return cmd
}

// showClients diagnoses and renders client panels.
func (a *app) showClients(ctx context.Context, ix *wireless.Index, views []wireless.ClientView, since time.Duration) error {
	cfg, err := a.config(ctx)
	if err != nil {
		return err
	}
	d, err := cfg.Diagnoser()
	if err != nil {
		return err
	}
	reports := make([]clientReport, 0, len(views))
	for i := range views {
		v := &views[i]
		reports = append(reports, clientReport{View: *v, AP: v.Client.APName, Diagnosis: d.Client(ix, v, a.trackOf(ctx, v, since))})
	}
	if a.json {
		return a.emitJSON(reports)
	}
	for i, rep := range reports {
		if i > 0 {
			a.printf("\n")
		}
		a.renderClient(&rep.View, rep.Diagnosis)
	}
	return nil
}

// noClient explains a query that matched no associated station: show
// what did match, such as a stale authentication session.
func (a *app) noClient(q wireless.Query, r wireless.Result) error {
	if a.json {
		return a.emitJSON(r)
	}
	if r.Empty() {
		a.printf(msgNotFound, q.String())
		return errNotFound
	}
	if err := a.renderResult(r); err != nil {
		return err
	}
	return errNotFound
}

func (a *app) renderClient(v *wireless.ClientView, rep diagnose.Report) {
	c := v.Client
	a.printf(msgClientTitle, c.MAC.H3C(), v.Controller.Label())
	a.printf(msgVerdict, verdict(rep))
	model, apIP := "-", "-"
	if v.AP != nil {
		model, apIP = dash(v.AP.Model), addrCell(v.AP.IP)
	}
	a.printf(msgLocation, c.APName, model, apIP, c.RadioID, c.Band(), c.Channel, dash(c.Bandwidth), macCell(c.BSSID))
	a.printf(msgNetwork, c.SSID, intCell(c.VLAN), addrCell(c.IPv4), addrCell(c.IPv6), dash(c.Username))
	a.printf(msgAccess+"\n", dash(v.Access.String()))
	if len(v.Sessions) == 0 {
		a.printf(msgNoSession)
	}
	for _, s := range v.Sessions {
		a.printf(msgSession, s.Kind, dash(s.Username), dash(s.Domain), dash(s.Method), intCell(s.InitialVLAN),
			intCell(s.AuthorizedVLAN), timeCell(s.OnlineSince), durationCell(s.Online))
	}
	if v.Chain.Template != "" {
		portal := ""
		if v.Chain.PortalURL != "" {
			portal = fmt.Sprintf(msgPortal, v.Chain.PortalURL)
		}
		a.printf(msgChain, v.Chain.Template, dash(v.Chain.Domain), dash(v.Chain.Scheme), dash(strings.Join(v.Chain.Servers, "/")), portal)
	}
	sig := rep.Signal
	dbm := ""
	if sig.Estimated {
		dbm = fmt.Sprintf(msgDBm, sig.DBm)
	}
	noise := "-"
	if sig.NoiseFloor != 0 {
		noise = fmt.Sprintf("%d dBm", sig.NoiseFloor)
	}
	usage := "-"
	if v.Radio != nil {
		usage = percentCell(v.Radio.Usage)
	}
	a.printf(msgLink, c.RSSI, dbm, noise, usage, dash(c.Mode), dash(c.Bandwidth), c.RxRate, c.TxRate, c.RxKbps, c.TxKbps)
	if len(rep.Quality.Factors) > 0 {
		a.printf(msgFactors, factorsText(rep.Quality))
	}
	a.printf(msgOnline, durationCell(c.Online), dash(c.Roam), c.SleepCount)
	a.printf(msgDiagnosis, levelWords[rep.Level.String()])
	hidden := 0
	for _, f := range rep.Findings {
		if f.Level == diagnose.LevelOK && !a.verbose {
			hidden++
			continue
		}
		prefix := fmt.Sprintf("  [%s] %-4s ", levelWords[f.Level.String()], layerWords[string(f.Layer)])
		a.printf("%s%s\n", prefix, wrap(safe(f.Message), panelWidth-displayWidth(prefix), strings.Repeat(" ", displayWidth(prefix))))
	}
	if hidden > 0 {
		a.printf(msgHiddenOK, hidden)
	}
}

// wrap breaks s into lines of at most width columns, indenting
// continuation lines.
func wrap(s string, width int, indent string) string {
	if width <= 10 || displayWidth(s) <= width {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := displayWidth(string(r))
		if w+rw > width {
			b.WriteString("\n" + indent)
			w = 0
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String()
}

// verdict condenses a diagnosis into one line an operator reads first.
func verdict(rep diagnose.Report) string {
	q := rep.Quality
	parts := []string{fmt.Sprintf(verdictQuality, q.Grade.Word(), q.Total)}
	if q.Grade == quality.GradeUnknown {
		parts = []string{verdictUnscored}
	}
	if q.Cause != quality.CauseNone {
		parts = append(parts, fmt.Sprintf(verdictCause, q.Cause.Word()))
	}
	if rep.Sticky.Suspected {
		parts = append(parts, fmt.Sprintf(verdictSticky, rep.Sticky.Confidence.Word()))
	}
	if rep.Track != nil && rep.Track.PingPong != nil {
		parts = append(parts, verdictPingPong)
	}
	if q.Cause != quality.CauseNone {
		parts = append(parts, q.Cause.Advice())
	}
	return strings.Join(parts, verdictSeparator)
}

func factorsText(q quality.Score) string {
	parts := make([]string, 0, len(q.Factors))
	for _, f := range quality.Factors() {
		if n, ok := q.Factors[f]; ok {
			parts = append(parts, fmt.Sprintf("%s %d", factorWords[f], n))
		}
	}
	return strings.Join(parts, "  ")
}
