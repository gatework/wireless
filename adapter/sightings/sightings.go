package sightings

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/store/disk"

	"github.com/gatework/wireless/roam"
)

const (
	journalDir  = "journal"
	dayLayout   = "2006-01-02"
	journalExt  = ".jsonl"
	maxJournal  = 256 << 20
	maxSighting = 64 << 10
)

// Journal is the station sighting history under a snapshot root: one
// JSON line per station per collection, in one file per UTC day. Files
// older than the retention are removed when new sightings are appended.
type Journal struct {
	dir       string
	retention time.Duration
	now       func() time.Time
}

// Open returns the sighting history kept in root/journal. A non-positive
// retention keeps seven days.
func Open(root string, retention time.Duration, now func() time.Time) *Journal {
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	if now == nil {
		now = time.Now
	}
	return &Journal{dir: filepath.Join(root, journalDir), retention: retention, now: now}
}

// Append adds sightings to their day files and prunes expired days.
func (j *Journal) Append(ctx context.Context, obs []roam.Observation) error {
	if len(obs) == 0 {
		return nil
	}
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return fmt.Errorf("snapshot: journal: %w", err)
	}
	byDay := map[string][]roam.Observation{}
	for _, o := range obs {
		day := o.At.UTC().Format(dayLayout)
		byDay[day] = append(byDay[day], o)
	}
	for day, list := range byDay {
		if err := j.appendDay(ctx, day, list); err != nil {
			return err
		}
	}
	return j.prune()
}

// Read returns the sightings at or after since, optionally only those
// keep accepts, in file order.
func (j *Journal) Read(ctx context.Context, since time.Time, keep func(roam.Observation) bool) ([]roam.Observation, error) {
	files, err := j.days()
	if err != nil {
		return nil, err
	}
	var out []roam.Observation
	for _, day := range files {
		if t, err := time.Parse(dayLayout, day); err == nil && t.Add(24*time.Hour).Before(since) {
			continue
		}
		if err := j.readDay(ctx, day, since, keep, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Days returns the UTC days the journal holds, oldest first.
func (j *Journal) Days() ([]string, error) { return j.days() }

func (j *Journal) appendDay(ctx context.Context, day string, list []roam.Observation) (err error) {
	f, err := disk.OpenAppend(filepath.Join(j.dir, day+journalExt))
	if err != nil {
		return fmt.Errorf("snapshot: journal: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("snapshot: journal: %w", cerr)
		}
	}()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, o := range list {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("snapshot: journal: %w", err)
		}
		if err := enc.Encode(o); err != nil {
			return fmt.Errorf("snapshot: journal: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("snapshot: journal: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("snapshot: journal: %w", err)
	}
	return nil
}

func (j *Journal) readDay(ctx context.Context, day string, since time.Time, keep func(roam.Observation) bool, out *[]roam.Observation) error {
	body, _, err := disk.ReadFile(ctx, filepath.Join(j.dir, day+journalExt), maxJournal)
	if err != nil {
		return fmt.Errorf("snapshot: journal %s: %w", day, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 4096), maxSighting)
	for sc.Scan() {
		var o roam.Observation
		if json.Unmarshal(sc.Bytes(), &o) != nil {
			continue // a torn final line after a crash is skipped
		}
		if !o.At.Before(since) && (keep == nil || keep(o)) {
			*out = append(*out, o)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("snapshot: journal %s: %w", day, err)
	}
	return nil
}

// days lists the journal day names in order.
func (j *Journal) days() ([]string, error) {
	entries, err := os.ReadDir(j.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot: journal: %w", err)
	}
	var out []string
	for _, e := range entries {
		day, ok := strings.CutSuffix(e.Name(), journalExt)
		if _, err := time.Parse(dayLayout, day); ok && err == nil && e.Type().IsRegular() {
			out = append(out, day)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (j *Journal) prune() error {
	days, err := j.days()
	if err != nil {
		return err
	}
	cutoff := j.now().Add(-j.retention).UTC().Format(dayLayout)
	for _, day := range days {
		if day < cutoff {
			if err := os.Remove(filepath.Join(j.dir, day+journalExt)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("snapshot: journal: %w", err)
			}
		}
	}
	return nil
}
