package cli

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/gatework/wireless"
)

func (a *app) apCommand() *cobra.Command {
	var weak int
	cmd := &cobra.Command{
		Use: "ap [AP名|IP|MAC|序列号]", Short: shortAP, Args: cobra.MaximumNArgs(1),
		Example: "  wireless ap                 # 全部 AP\n  wireless ap 6FAP06          # 详情、射频、BSS 与终端\n  wireless ap 6FAP06 --weak 20",
		RunE: func(cmd *cobra.Command, args []string) error {
			ix, err := a.index(cmd.Context(), wireless.DimensionAccessPoints, wireless.DimensionBSS, wireless.DimensionClients)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				var views []wireless.APView
				for v := range ix.AccessPoints() {
					views = append(views, v)
				}
				if a.json {
					return a.emitJSON(views)
				}
				a.printf(msgSectionAPs, len(views))
				// Problems first: APs that are not running, then by load.
				slices.SortStableFunc(views, func(x, y wireless.APView) int {
					return cmp.Or(cmp.Compare(boolRank(x.AP.Running()), boolRank(y.AP.Running())), cmp.Compare(y.Clients, x.Clients))
				})
				return a.list(apsTable(views))
			}
			q, err := wireless.ParseQuery(args[0])
			if err != nil {
				return err
			}
			views := ix.Find(q).APs
			if len(views) == 0 {
				a.printf(msgNotFound, q.String())
				return errNotFound
			}
			details := make([]apDetail, 0, len(views))
			for _, v := range views {
				details = append(details, newAPDetail(ix, v, weak))
			}
			if a.json {
				return a.emitJSON(details)
			}
			for i, d := range details {
				if i > 0 {
					a.printf("\n")
				}
				if err := a.renderAP(d); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&weak, "weak", 0, flagWeak)
	return cmd
}

// apDetail is one AP with its BSSs and stations.
type apDetail struct {
	wireless.APView
	BSS     []wireless.BSS        `json:"bss"`
	Clients []wireless.ClientView `json:"clients"`
}

func newAPDetail(ix *wireless.Index, v wireless.APView, weak int) apDetail {
	d := apDetail{APView: v}
	if s, ok := ix.Snapshot(v.Controller.Host); ok {
		for _, b := range s.BSS.Facts {
			if b.APName == v.AP.Name {
				d.BSS = append(d.BSS, b)
			}
		}
	}
	for c := range ix.Clients() {
		if c.Controller.Host == v.Controller.Host && c.Client.APName == v.AP.Name && (weak <= 0 || c.Client.RSSI < weak) {
			d.Clients = append(d.Clients, c)
		}
	}
	slices.SortFunc(d.Clients, func(x, y wireless.ClientView) int { return cmp.Compare(x.Client.RSSI, y.Client.RSSI) })
	return d
}

func (a *app) renderAP(d apDetail) error {
	ap := d.AP
	a.printf(msgAPTitle, ap.Name, d.Controller.Label())
	a.printf(msgAPInfo, dash(string(ap.State)), dash(ap.Model), dash(ap.Serial), addrCell(ap.IP), macCell(ap.MAC), dash(ap.Group),
		dash(ap.Software), durationCell(ap.Online), durationCell(ap.Uptime), dash(ap.RebootReason), dash(ap.Power), ap.LostEchoes, ap.EchoRequests)
	radios := newTable(headRadios...)
	for _, r := range ap.Radios {
		state := "Down"
		if r.Up {
			state = "Up"
		}
		channel := intCell(r.Channel)
		if r.ChannelMode != "" {
			channel += "(" + r.ChannelMode + ")"
		}
		noise := "-"
		if r.NoiseFloor != 0 {
			noise = fmt.Sprintf("%d dBm", r.NoiseFloor)
		}
		radios.add(fmt.Sprint(r.ID), state, dash(r.Type), channel, dash(r.Bandwidth), fmt.Sprintf("%d dBm", r.MaxPower),
			percentCell(r.Usage), noise, macCell(r.BSSID))
	}
	a.printf("\n")
	if err := radios.render(a.env.Stdout); err != nil {
		return err
	}
	if len(d.BSS) > 0 {
		bss := newTable(headBSS...)
		for _, b := range d.BSS {
			bss.add(fmt.Sprint(b.RadioID), macCell(b.BSSID), b.SSID, b.Template, intCell(b.VLAN), dash(b.AKM), dash(b.UserAuth))
		}
		a.printf("\n")
		if err := bss.render(a.env.Stdout); err != nil {
			return err
		}
	}
	a.printf("\n"+msgAPClientsTitle, len(d.Clients))
	t := newTable(headAPClients...)
	for _, v := range d.Clients {
		c := v.Client
		t.add(macCell(c.MAC), addrCell(c.IPv4), dash(username(v)), c.SSID, fmt.Sprintf("R%d/%s", c.RadioID, c.Band()),
			intCell(c.RSSI), fmt.Sprintf("%.0f/%.0f", c.RxRate, c.TxRate), dash(v.Access.String()), durationCell(c.Online))
	}
	return a.list(t)
}

// boolRank orders false before true.
func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}
