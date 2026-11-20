package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gatework/net-connector/connector"
	"github.com/gatework/net-connector/transport"
	"github.com/gatework/net-connector/transport/ssh"
	"github.com/gatework/net-connector/vendors"

	"github.com/gatework/netops/assess"
	nbootstrap "github.com/gatework/netops/bootstrap"
	"github.com/gatework/netops/credential"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/inventory"
	"github.com/gatework/netops/ops"
	"github.com/gatework/netops/secret"
	"github.com/gatework/netops/store/journal"
	"github.com/gatework/netops/store/snapshot"

	"github.com/gatework/wireless/adapter/sightings"
	"github.com/gatework/wireless/diagnose"
	"github.com/gatework/wireless/health"
	"github.com/gatework/wireless/vendors/h3c"
)

// ErrCredentials reports missing device credentials.
var ErrCredentials = errors.New("bootstrap: device username and password required (NC_H3C_WIRELESS_USERNAME/PASSWORD or NC_DEVICE_USERNAME/PASSWORD)")

// ErrNoTargets reports that no controller matched.
var ErrNoTargets = errors.New("bootstrap: no controllers configured or selected")

// Vendor returns the H3C vendor in the configured time zone.
func (c *Config) Vendor() *h3c.Vendor { return h3c.New(h3c.Options{Location: c.Location}) }

// Store opens the local capture cache.
func (c *Config) Store() (*snapshot.Store, error) {
	s, err := snapshot.Open(c.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return s, nil
}

// Sightings returns the station sighting journal kept beside the cache for
// the configured history.
func (c *Config) Sightings() *sightings.Journal { return sightings.Open(c.CacheDir, c.History, nil) }

// Diagnoser returns the station diagnoser.
func (c *Config) Diagnoser() (*diagnose.Diagnoser, error) {
	d, err := diagnose.New(c.Models)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return d, nil
}

// Inspector returns the health inspector under the configured policy.
func (c *Config) Inspector(ctx context.Context) (*health.Inspector, error) {
	var policy assess.Policy
	if c.PolicyPath != "" {
		data, _, err := nbootstrap.ReadFile(ctx, c.PolicyPath, false)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: policy %s: %w", c.PolicyPath, err)
		}
		if policy, err = assess.DecodePolicy(data); err != nil {
			return nil, fmt.Errorf("bootstrap: policy %s: %w", c.PolicyPath, err)
		}
	}
	in, err := health.New(policy, c.Vendor(), health.Options{Quality: c.Models.Quality, Roaming: c.Models.Roaming})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return in, nil
}

// credentials maps the environment to device credentials.
func (c *Config) credentials() credential.Provider { return credential.Env{Environ: c.env} }

// HasCredentials reports whether device credentials are configured, so
// that queries can refresh the cache.
func (c *Config) HasCredentials(ctx context.Context) bool {
	_, err := c.credentials().Lookup(ctx, device.Device{Platform: h3c.Platform})
	return err == nil
}

// Redactor masks the configured secrets in journaled commands.
func (c *Config) Redactor(ctx context.Context) secret.Redactor {
	creds, _ := c.credentials().Lookup(ctx, device.Device{Platform: h3c.Platform})
	return secret.NewRedactor(4, creds.Secrets()...)
}

// Dialer returns the device port: the net-connector dialer with
// credentials and SSH settings. Host keys are checked strictly unless
// configured otherwise.
func (c *Config) Dialer(ctx context.Context) (ops.Dialer, error) {
	if !c.HasCredentials(ctx) {
		return nil, ErrCredentials
	}
	sshDialer, err := ssh.New(ssh.Options{
		KnownHosts: c.SSH.KnownHosts, HostKeys: ssh.Policy(c.SSH.HostKeyPolicy), Jump: c.SSH.JumpHost,
		Timeout: durationOr(c.SSH.LoginTimeout, 30*time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: ssh: %w", ErrConfig, err)
	}
	d, err := connector.NewDialer(connector.Options{
		Registry:    vendors.Builtin(),
		Credentials: c.credentials(),
		Transport:   transport.Retrying{Dialer: sshDialer, Retries: c.SSH.ConnectRetries},
		Port:        c.SSH.Port,
		Timeout:     durationOr(c.SSH.CommandTimeout, 5*time.Minute),
		// Large controllers print tens of megabytes of client detail.
		MaxOutput: 64 << 20,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: ssh: %w", ErrConfig, err)
	}
	return d.Port(), nil
}

// Journal opens the change journal of station actions.
func (c *Config) Journal() (*journal.Journal, error) {
	j, err := journal.Open(c.JournalDir, nil)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: journal: %w", err)
	}
	return j, nil
}

// Targets returns the controllers to visit: the configured list plus the
// Netdisco inventory when configured, filtered by selectors (an address, a
// prefix, a name fragment or any device selector term; several selectors
// add up).
func (c *Config) Targets(ctx context.Context, selectors []string) ([]device.Device, error) {
	sel, err := device.ParseSelector(selectors...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	static := make([]device.Device, 0, len(c.Controllers))
	for _, e := range c.Controllers {
		addr, err := netip.ParseAddr(e.Host)
		if err != nil {
			return nil, fmt.Errorf("%w: controller %q", ErrConfig, e.Host)
		}
		static = append(static, device.Device{Name: e.Name, Mgmt: addr, Platform: h3c.Platform})
	}
	sources := []inventory.Source{inventory.Static{Label: "controllers", Records: static}}
	if c.netdisco != nil {
		nd := *c.netdisco
		nd.URL = firstNonEmpty(nd.URL, c.env["ND_URL"])
		if len(nd.Platforms) == 0 {
			nd.Platforms = []string{h3c.Platform}
		}
		sources = append(sources, inventory.Netdisco{Config: nd, Classifier: vendors.Builtin(), Credentials: inventory.NetdiscoCredentials{
			Username: c.env["ND_USERNAME"], Password: secret.New(c.env["ND_PASSWORD"]), APIKey: secret.New(c.env["ND_API_KEY"]),
			DBHost: c.env["ND_DB_HOST"], DBName: c.env["ND_DB_NAME"], DBUser: c.env["ND_DB_USER"], DBPassword: secret.New(c.env["ND_DB_PASS"]),
		}})
	}
	// Netdisco first, so that the operator's controller list wins.
	if len(sources) == 2 {
		sources[0], sources[1] = sources[1], sources[0]
	}
	inv, _, _, err := inventory.Load(ctx, sources...)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: inventory: %w", err)
	}
	out := inv.Select(sel)
	if len(out) == 0 {
		return nil, ErrNoTargets
	}
	return out, nil
}

func durationOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
