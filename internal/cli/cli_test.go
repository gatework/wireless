package cli_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/capture"
	"github.com/gatework/netops/store/snapshot"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/adapter/sightings"
	"github.com/gatework/wireless/internal/cli"
	"github.com/gatework/wireless/roam"
	"github.com/gatework/wireless/vendors/h3c"
)

// snapshotRoot writes the H3C fixtures as one controller's capture.
func snapshotRoot(t *testing.T) string {
	t.Helper()
	files := map[string]string{
		h3c.CommandClients: "clients.txt", h3c.CommandAccessPoints: "aps.txt", h3c.CommandBSS: "bss.txt",
		h3c.CommandDot1X: "dot1x.txt", h3c.CommandMAC: "mac.txt", h3c.CommandConflicts: "conflicts.txt",
		h3c.CommandBlocked: "blocked.txt", h3c.CommandConfiguration: "config.txt",
	}
	c := capture.Capture{Host: netip.MustParseAddr("198.51.100.1"), Prompt: "<AC-1>"}
	for command, name := range files {
		body, err := os.ReadFile(filepath.Join("..", "..", "vendors", "h3c", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		c.Outputs = append(c.Outputs, capture.Output{Command: command, Raw: string(body),
			RecordedAt: time.Date(2026, 11, 13, 7, 47, 0, 0, time.UTC)})
	}
	root := t.TempDir()
	st, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	return root
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Run(t.Context(), args, cli.Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut, Home: t.TempDir(),
		Environ: []string{"WIRELESS_CONFIG=" + filepath.Join(t.TempDir(), "absent.yml")},
	})
	return code, out.String(), errOut.String()
}

func TestRun_queries(t *testing.T) {
	t.Parallel()
	root := snapshotRoot(t)
	tests := []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"find", "192.0.2.10"}, cli.ExitOK, []string{"AP-1F-01", "Corp", "alice", "802.1X"}},
		{[]string{"find", "nobody-here"}, cli.ExitIncomplete, []string{"未找到"}},
		{[]string{"client", "0200-5e10-0001"}, cli.ExitOK, []string{"授权VLAN 120", "corp-domain", "信道 44", "诊断", "利用率 82%"}},
		{[]string{"client", "0600-5e10-0002"}, cli.ExitOK, []string{"PSK+MAC", "随机 MAC", "冲突"}},
		{[]string{"ap", "AP-1F-01"}, cli.ExitOK, []string{"WA6330", "0200-5e20-0022", "终端（1"}},
		{[]string{"auth", "--method", "dot1x"}, cli.ExitOK, []string{"alice", "corp-domain"}},
		{[]string{"auth", "--vlan", "200-210"}, cli.ExitOK, []string{"staff-domain"}},
		{[]string{"conflicts", "--ip", "192.0.2.0/24"}, cli.ExitOK, []string{"192.0.2.11", "2"}},
		{[]string{"summary"}, cli.ExitOK, []string{"AC-1", "1/2", "3/64", "Corp"}},
		{[]string{"health"}, cli.ExitOK, []string{"AP 未处于 Run 状态", "TKIP"}},
		{[]string{"kick", "192.0.2.10", "--plan"}, cli.ExitOK, []string{"reset wlan client mac-address 0200-5e10-0001"}},
		{[]string{"kick", "alice", "--plan"}, cli.ExitOK, []string{"0200-5e10-0001"}},
		{[]string{"kick", "0200-5e10-00ff", "--plan"}, cli.ExitIncomplete, []string{"不在线"}},
		{[]string{"block", "add", "192.0.2.10", "--plan"}, cli.ExitOK, []string{"wlan static-blacklist mac-address 0200-5e10-0001 ; return ; reset wlan client"}},
		{[]string{"block", "add", "０２００－５ｅ１０－００ｆｆ", "--plan"}, cli.ExitOK, []string{"wlan static-blacklist mac-address 0200-5e10-00ff ; return"}},
		{[]string{"block", "add", "5e10", "--plan"}, cli.ExitIncomplete, []string{"--all"}},
		{[]string{"block", "add", "0200-5e10-0001"}, cli.ExitIncomplete, []string{"--yes"}},
		{[]string{"192.0.2.10"}, cli.ExitOK, []string{"结论", "质量"}},
		{[]string{"rf"}, cli.ExitOK, []string{"信道规划", "default-group"}},
		{[]string{"roam"}, cli.ExitOK, []string{"没有漫游轨迹", "疑似粘滞"}},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			code, out, errOut := run(t, append(tc.args, "--snapshot", root)...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestRun_findJSON(t *testing.T) {
	t.Parallel()
	code, out, _ := run(t, "find", "alice", "--json", "--snapshot", snapshotRoot(t))
	if code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Freshness struct {
			Mode        string            `json:"mode"`
			Controllers []json.RawMessage `json:"controllers"`
		} `json:"freshness"`
		Result struct {
			Clients []struct {
				Client struct {
					MAC string `json:"mac"`
				} `json:"client"`
				Access string `json:"access"`
			} `json:"clients"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Freshness.Mode != "auto" || len(doc.Freshness.Controllers) != 1 {
		t.Errorf("freshness = %+v", doc.Freshness)
	}
	r := doc.Result
	if len(r.Clients) != 1 || r.Clients[0].Client.MAC != "02:00:5e:10:00:01" || r.Clients[0].Access != "802.1X" {
		t.Errorf("json = %+v", r)
	}
}

func TestRun_emptySnapshot(t *testing.T) {
	t.Parallel()
	code, _, errOut := run(t, "find", "x", "--snapshot", t.TempDir())
	if code != cli.ExitIncomplete || !strings.Contains(errOut, "wireless collect") {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
}

func TestRun_roamTimeline(t *testing.T) {
	t.Parallel()
	root := snapshotRoot(t)
	m, _ := wireless.ParseMAC("0200-5e10-0001")
	now := time.Now().UTC().Truncate(time.Minute)
	var obs []roam.Observation
	for i, ap := range []string{"AP-1F-01", "AP-1F-02", "AP-1F-01", "AP-1F-02"} {
		obs = append(obs, roam.Observation{At: now.Add(time.Duration(i-4) * 2 * time.Minute), Host: "198.51.100.1", MAC: m, AP: ap, Channel: 44, RSSI: 20, Online: time.Minute})
	}
	if err := sightings.Open(root, 0, nil).Append(t.Context(), obs); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "roam", "alice", "--cache", root)
	if code != cli.ExitOK || !strings.Contains(out, "乒乓漫游：AP-1F-01↔AP-1F-02") || !strings.Contains(out, "漫游") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, "health", "--cache", root)
	if code != cli.ExitOK || !strings.Contains(out, "终端乒乓漫游") {
		t.Errorf("health exit %d:\n%s", code, out)
	}
}

func TestRun_cacheLifecycle(t *testing.T) {
	t.Parallel()
	src := snapshotRoot(t)
	home := t.TempDir()
	env := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cli.Run(t.Context(), args, cli.Env{
			Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut, Home: home,
			Environ: []string{"WIRELESS_CONFIG=" + filepath.Join(home, "absent.yml")},
		})
		return code, out.String(), errOut.String()
	}
	if code, _, errOut := env("summary"); code != cli.ExitIncomplete || !strings.Contains(errOut, "--snapshot") {
		t.Fatalf("empty cache: %d %s", code, errOut)
	}
	code, out, errOut := env("summary", "--snapshot", src)
	if code != cli.ExitOK || !strings.Contains(errOut, "导入 1 台") || !strings.Contains(errOut, "数据：1 台 AC") {
		t.Fatalf("import: %d\n%s\n%s", code, out, errOut)
	}
	// No flag needed afterwards; nothing is imported again.
	code, again, errOut := env("summary")
	if code != cli.ExitOK || again != out || strings.Contains(errOut, "导入") || !strings.Contains(errOut, "仅用缓存") {
		t.Fatalf("cached run: %d\n%s\n%s", code, again, errOut)
	}
	if code, out, _ := env("status"); code != cli.ExitOK || !strings.Contains(out, "AC-1") || !strings.Contains(out, "天前") {
		t.Errorf("status: %d\n%s", code, out)
	}
	if code, _, errOut := env("summary", "-c", "nope"); code != cli.ExitIncomplete || !strings.Contains(errOut, "可选：AC-1") {
		t.Errorf("no match: %d %s", code, errOut)
	}
	if code, _, errOut := env("fnd", "192.0.2.10"); code != cli.ExitIncomplete || !strings.Contains(errOut, "find") {
		t.Errorf("suggestion: %d %s", code, errOut)
	}
	if code, _, errOut := env("find", ""); code != cli.ExitError || !strings.Contains(errOut, "查询内容为空") {
		t.Errorf("empty query: %d %s", code, errOut)
	}
	if code, _, _ := env("health", "--fail-on", "medium"); code != cli.ExitIncomplete {
		t.Errorf("fail-on exit = %d", code)
	}
	if code, out, _ := env("conflicts"); code != cli.ExitOK || !strings.Contains(out, "两 MAC 反复互抢") && !strings.Contains(out, "偶发") {
		t.Errorf("conflicts: %d\n%s", code, out)
	}
}
