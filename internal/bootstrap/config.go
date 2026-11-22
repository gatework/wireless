package bootstrap

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"go.yaml.in/yaml/v3"

	nbootstrap "github.com/gatework/netops/bootstrap"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/inventory"

	"github.com/gatework/wireless"
	"github.com/gatework/wireless/diagnose"
	"github.com/gatework/wireless/internal/workflow"
)

// ErrConfig reports an invalid configuration or credentials file.
var ErrConfig = nbootstrap.ErrConfig

// Options locates the configuration.
type Options struct {
	// ConfigPath is an explicit wireless.yml; empty means discovery.
	ConfigPath string
	// EnvPath is an explicit credentials file; empty means the .env next
	// to the configuration, if any.
	EnvPath string
	// Environ is the process environment, as os.Environ returns it.
	Environ []string
	// Home is the user's home directory, for "~" and default locations.
	Home string
}

// file is the wireless.yml document.
type file struct {
	Snapshot    string                    `yaml:"snapshot"`
	Cache       cacheFile                 `yaml:"cache"`
	Parallel    int                       `yaml:"parallel"`
	Timezone    string                    `yaml:"timezone"`
	Controllers []controllerEntry         `yaml:"controllers"`
	SSH         sshFile                   `yaml:"ssh"`
	Thresholds  yaml.Node                 `yaml:"thresholds"`
	Quality     yaml.Node                 `yaml:"quality"`
	Roaming     yaml.Node                 `yaml:"roaming"`
	HistoryDays int                       `yaml:"history_days"`
	Policy      string                    `yaml:"policy"`
	Journal     string                    `yaml:"journal"`
	Netdisco    *inventory.NetdiscoConfig `yaml:"netdisco"`
	Watch       watchFile                 `yaml:"watch"`
}

// watchFile configures wireless watch: its schedules and where its events
// go.
type watchFile struct {
	Interval time.Duration `yaml:"interval"`
	Sweep    string        `yaml:"sweep"`
	Events   eventsFile    `yaml:"events"`
}

type eventsFile struct {
	File        string `yaml:"file"`
	Webhook     string `yaml:"webhook"`
	MinSeverity string `yaml:"min_severity"`
}

type cacheFile struct {
	Dir        string                   `yaml:"dir"`
	Refresh    string                   `yaml:"refresh"`
	Timeout    time.Duration            `yaml:"timeout"`
	RetryAfter time.Duration            `yaml:"retry_after"`
	TTL        map[string]time.Duration `yaml:"ttl"`
}

type controllerEntry struct {
	Host string `yaml:"host"`
	Name string `yaml:"name"`
}

type sshFile struct {
	Port           int           `yaml:"port"`
	HostKeyPolicy  string        `yaml:"host_key_policy"`
	KnownHosts     string        `yaml:"known_hosts"`
	JumpHost       string        `yaml:"jump_host"`
	LoginTimeout   time.Duration `yaml:"login_timeout"`
	CommandTimeout time.Duration `yaml:"command_timeout"`
	ConnectRetries int           `yaml:"connect_retries"`
}

// Config is the resolved configuration.
type Config struct {
	// Path is the configuration file read, or empty when none was found.
	Path string
	// Snapshot is an external snapshot directory imported into the cache
	// on use; it is only read. Empty when none is configured.
	Snapshot string
	// CacheDir is the local capture cache every query reads.
	CacheDir string
	// Cache is the freshness policy of the cache.
	Cache       workflow.Policy
	Parallel    int
	Location    *time.Location
	Controllers []controllerEntry
	SSH         sshFile
	// Models holds the diagnosis thresholds, quality profile and roaming
	// parameters, each the defaults overlaid by wireless.yml.
	Models diagnose.Options
	// History is how long station sightings are kept.
	History    time.Duration
	PolicyPath string
	JournalDir string
	// DataDir holds the tool's own data: run history and the event log.
	DataDir string
	// Watch configures wireless watch.
	Watch    Watch
	netdisco *inventory.NetdiscoConfig
	env      map[string]string
}

// Load reads the configuration and credentials. A missing configuration
// file is not an error when it was discovered rather than named.
func Load(ctx context.Context, o Options) (*Config, error) {
	process := nbootstrap.Environ(o.Environ)
	path, explicit := o.ConfigPath, o.ConfigPath != ""
	if !explicit {
		path = nbootstrap.Env{App: "wireless", Environ: process, Home: o.Home}.Discover()
	}
	var f file
	c := &Config{Models: diagnose.DefaultOptions()}
	if path != "" {
		data, found, err := nbootstrap.ReadFile(ctx, path, !explicit)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: read %s: %w", path, err)
		}
		if found {
			if err := nbootstrap.DecodeYAML(data, &f); err != nil {
				return nil, fmt.Errorf("bootstrap: %s: %w", path, err)
			}
			c.Path = path
		}
	}
	env, err := nbootstrap.LoadEnv(ctx, o.EnvPath, c.Path, process)
	if err != nil {
		return nil, err
	}
	c.env = env
	if err := c.apply(f, o.Home); err != nil {
		return nil, err
	}
	return c, nil
}

// Env returns one variable of the merged environment: the process
// environment over the credentials file.
func (c *Config) Env(name string) string { return c.env[name] }

func resolve(p, home string) string {
	if p == "" {
		return ""
	}
	return nbootstrap.ResolvePath(p, ".", home)
}

func (c *Config) apply(f file, home string) error {
	data := filepath.Join(home, ".local", "share", "wireless")
	c.Snapshot = resolve(firstNonEmpty(c.env["WIRELESS_SNAPSHOT"], f.Snapshot), home)
	c.CacheDir = resolve(firstNonEmpty(c.env["WIRELESS_CACHE"], f.Cache.Dir, filepath.Join(data, "cache")), home)
	policy, err := cachePolicy(f.Cache)
	if err != nil {
		return err
	}
	c.Cache = policy
	c.Parallel = f.Parallel
	if c.Parallel <= 0 {
		c.Parallel = 8
	}
	c.Location = time.Local
	if f.Timezone != "" {
		loc, err := time.LoadLocation(f.Timezone)
		if err != nil {
			return fmt.Errorf("%w: timezone %q", ErrConfig, f.Timezone)
		}
		c.Location = loc
	}
	for _, overlay := range []struct {
		name string
		node yaml.Node
		into any
	}{
		{"thresholds", f.Thresholds, &c.Models.Thresholds},
		{"quality", f.Quality, &c.Models.Quality},
		{"roaming", f.Roaming, &c.Models.Roaming},
	} {
		if overlay.node.IsZero() {
			continue
		}
		if err := overlay.node.Decode(overlay.into); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrConfig, overlay.name, err)
		}
	}
	if _, err := diagnose.New(c.Models); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	c.History = time.Duration(max(f.HistoryDays, 0)) * 24 * time.Hour
	c.Controllers, c.SSH = f.Controllers, f.SSH
	c.PolicyPath = resolve(f.Policy, home)
	c.JournalDir = resolve(firstNonEmpty(f.Journal, filepath.Join(data, "actions")), home)
	c.netdisco = f.Netdisco
	c.DataDir = data
	w, err := watchConfig(f.Watch, c.Location, data, home)
	if err != nil {
		return err
	}
	c.Watch = w
	return nil
}

// cachePolicy overlays the cache section on the default policy.
func cachePolicy(f cacheFile) (workflow.Policy, error) {
	p := workflow.DefaultPolicy()
	if f.Refresh != "" {
		p.Mode = workflow.Mode(f.Refresh)
	}
	if f.Timeout > 0 {
		p.Timeout = f.Timeout
	}
	if f.RetryAfter > 0 {
		p.RetryAfter = f.RetryAfter
	}
	known := wireless.Dimensions()
	for name, ttl := range f.TTL {
		d := evidence.Dimension(name)
		if !slices.Contains(known, d) {
			return p, fmt.Errorf("%w: cache.ttl: unknown dimension %q", ErrConfig, name)
		}
		p.TTL[d] = ttl
	}
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("%w: cache: %w", ErrConfig, err)
	}
	return p, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
