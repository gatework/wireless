package action_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/device"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/action"
)

// renderer is a fake vendor whose readbacks are scripted.
type renderer struct{}

func (renderer) Render(kind action.Kind, mac wireless.MAC) (action.Script, error) {
	s := action.Script{Commands: []string{string(kind) + " " + mac.H3C()}, Readback: "show " + mac.H3C()}
	if kind == action.KindBlock {
		s.Rollback = []string{"unblock " + mac.H3C()}
	}
	return s, nil
}

func (renderer) Observe(_ action.Kind, _ wireless.MAC, response string) (action.State, error) {
	switch response {
	case "present":
		return action.State{Present: true, Online: time.Hour}, nil
	case "reassociated":
		return action.State{Present: true, Online: time.Second}, nil
	case "absent":
		return action.State{}, nil
	}
	return action.State{}, errors.New("unexpected readback")
}

// session replays readbacks and records writes.
type session struct {
	readbacks []string
	writes    []string
}

func (s *session) Read(context.Context) (action.State, error) {
	next := s.readbacks[0]
	s.readbacks = s.readbacks[1:]
	return renderer{}.Observe("", wireless.MAC{}, next)
}

func (s *session) Write(_ context.Context, c change.Command) error {
	s.writes = append(s.writes, c.Text)
	return nil
}

type journal struct{ records []apply.Record }

func (j *journal) Write(_ context.Context, r apply.Record) error {
	j.records = append(j.records, r)
	return nil
}

var (
	ac   = device.Device{ID: "ac1", Mgmt: netip.MustParseAddr("198.51.100.1"), Name: "AC1"}
	meta = change.Meta{ID: "act-1", Created: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)}
)

func mac(t *testing.T) wireless.MAC {
	t.Helper()
	m, err := wireless.ParseMAC("0200-5e10-0001")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		kind      action.Kind
		readbacks []string
		status    apply.Status
		writes    int
	}{
		{"kick verified when gone", action.KindKick, []string{"present", "absent"}, apply.StatusVerified, 1},
		{"kick verified when reassociated", action.KindKick, []string{"present", "reassociated"}, apply.StatusVerified, 1},
		{"kick of an absent station is a no-op", action.KindKick, []string{"absent"}, apply.StatusSatisfied, 0},
		{"kick without effect is uncertain", action.KindKick, []string{"present", "present"}, apply.StatusUncertain, 1},
		{"block verified", action.KindBlock, []string{"absent", "present"}, apply.StatusVerified, 1},
		{"block of a listed station is a no-op", action.KindBlock, []string{"present"}, apply.StatusSatisfied, 0},
		{"unblock verified", action.KindUnblock, []string{"present", "absent"}, apply.StatusVerified, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := action.NewPlan(meta, action.Request{Kind: tc.kind, MAC: mac(t), Device: ac}, renderer{})
			if err != nil {
				t.Fatal(err)
			}
			s := &session{readbacks: tc.readbacks}
			rec, _ := apply.Run(t.Context(), apply.Request[action.State]{Plan: p, Session: s, Journal: &journal{}})
			if rec.Status != tc.status || len(s.writes) != tc.writes {
				t.Errorf("status %s writes %v", rec.Status, s.writes)
			}
		})
	}
}

func TestRequest_Validate(t *testing.T) {
	t.Parallel()
	group, _ := wireless.ParseMAC("0100-5e00-0001")
	for name, r := range map[string]action.Request{
		"unknown kind":   {Kind: "reboot", MAC: mac(t), Device: ac},
		"group MAC":      {Kind: action.KindKick, MAC: group, Device: ac},
		"no device":      {Kind: action.KindKick, MAC: mac(t)},
		"kick with kick": {Kind: action.KindKick, MAC: mac(t), Device: ac, Kick: true},
	} {
		if _, err := action.NewPlan(meta, r, renderer{}); !errors.Is(err, action.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBatch_andCodec(t *testing.T) {
	t.Parallel()
	ac2 := device.Device{ID: "ac2", Mgmt: netip.MustParseAddr("198.51.100.2")}
	plans, err := action.Batch(meta, action.KindBlock, mac(t), []device.Device{ac, ac2},
		func(d device.Device) bool { return d.ID == "ac2" }, renderer{})
	if err != nil || len(plans) != 2 {
		t.Fatal(err)
	}
	if got := plans[1].Commands(); len(got) != 2 || plans[0].Meta().ID == plans[1].Meta().ID {
		t.Errorf("online controller not kicked after block: %v", got)
	}
	e, _ := plans[1].Envelope()
	codec, _ := action.Codec()
	body, _ := jsonMarshal(e)
	back, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := action.Of(back)
	if !ok || !c.Kick || !slices.Equal(c.Script.Rollback, []string{"unblock " + mac(t).H3C()}) {
		t.Errorf("decoded %+v", c)
	}
}
