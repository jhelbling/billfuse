package watch

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jhelbling/billfuse/internal/sev"
)

var nowFn = time.Now

type Config struct {
	Collector    Collector
	Actor        Actor
	Notifiers    []Notifier
	Limits       Limits
	Interval     time.Duration // between cycles (default 60s)
	Window       time.Duration // usage window per cycle (default 10m)
	Delay        time.Duration // metric ingestion delay to skip (gcp ~4m, aws ~2m)
	Cooldown     time.Duration // re-alert interval for a still-firing alert (default 30m)
	MinNotify    sev.Severity  // alerts below this only go to the log
	Act          bool          // really trip the kill switch (default: dry-run)
	HeartbeatURL string
	State        *State
	Log          io.Writer
}

type CycleResult struct {
	At       time.Time    `json:"at"`
	Stats    []*ScopeStat `json:"scopes"`
	Alerts   []Alert      `json:"alerts"`
	Actions  []string     `json:"actions,omitempty"`
	Warnings []string     `json:"warnings,omitempty"`
}

func (c *Config) defaults() {
	if c.Interval == 0 {
		c.Interval = time.Minute
	}
	if c.Window == 0 {
		c.Window = 10 * time.Minute
	}
	if c.Cooldown == 0 {
		c.Cooldown = 30 * time.Minute
	}
	if c.State == nil {
		c.State = LoadState("")
	}
	if c.Log == nil {
		c.Log = io.Discard
	}
}

// Cycle runs one poll -> evaluate -> alert -> act pass.
func Cycle(ctx context.Context, c *Config) (*CycleResult, error) {
	c.defaults()
	now := nowFn()
	end := now.Add(-c.Delay).Truncate(time.Minute)
	start := end.Add(-c.Window)
	dayStart := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
	if end.Sub(dayStart) < time.Minute {
		dayStart = end.Add(-time.Minute)
	}

	recent, warns, err := c.Collector.Collect(ctx, start, end)
	if err != nil {
		return nil, err
	}
	today, w2, err := c.Collector.Collect(ctx, dayStart, end)
	if err != nil {
		return nil, err
	}
	warns = append(warns, w2...)

	stats := Rollup(recent, today, c.Window.Minutes())
	res := &CycleResult{At: now.UTC(), Warnings: dedupe(warns)}
	for _, s := range stats {
		res.Stats = append(res.Stats, s)
	}
	sort.Slice(res.Stats, func(i, j int) bool { return res.Stats[i].PerHour > res.Stats[j].PerHour })

	alerts := Evaluate(stats, recent, c.Limits, c.State)
	res.Alerts = alerts

	for _, a := range alerts {
		// Kill switch: once per scope per UTC day.
		actionText := ""
		if a.Trip && c.Actor != nil {
			key := a.Cloud + "|" + a.Scope + "|" + now.UTC().Format("2006-01-02")
			if !c.Act {
				key = "dry-run|" + key
			}
			if _, done := c.State.Acted[key]; !done {
				out, err := c.Actor.Act(ctx, a.Scope, recent, !c.Act)
				if err != nil {
					out += "\nKILL SWITCH FAILED: " + err.Error()
				}
				if err == nil {
					c.State.Acted[key] = now
				}
				actionText = out
				res.Actions = append(res.Actions, out)
			}
		}
		// Throttle repeats of a still-firing alert.
		if last, ok := c.State.LastSent[a.Key]; ok && !a.Resolved && actionText == "" && now.Sub(last) < c.Cooldown {
			continue
		}
		body := a.Detail
		if actionText != "" {
			body = strings.TrimSpace(body + "\n" + actionText)
		}
		fmt.Fprintf(c.Log, "%s ALERT %s %s\n", now.Format("15:04:05"), a.Severity, a.Title)
		if a.Severity < c.MinNotify && !a.Resolved {
			continue
		}
		if a.Resolved && !wasNotified(c.State, a.Key) {
			continue
		}
		msg := Message{Severity: a.Severity, Title: a.Title, Body: body, Time: now}
		for _, n := range c.Notifiers {
			if err := n.Send(ctx, msg); err != nil {
				res.Warnings = append(res.Warnings, n.Name()+" notify failed: "+err.Error())
			}
		}
		if a.Resolved {
			delete(c.State.LastSent, a.Key)
		} else {
			c.State.LastSent[a.Key] = now
		}
	}
	if err := c.State.Save(); err != nil {
		res.Warnings = append(res.Warnings, "state save: "+err.Error())
	}
	return res, nil
}

func wasNotified(st *State, key string) bool { _, ok := st.LastSent[key]; return ok }

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Run loops until ctx is cancelled. The heartbeat is pinged after every cycle
// (with /fail on errors) so a dead watcher is itself noticed.
func Run(ctx context.Context, c *Config, onCycle func(*CycleResult, error)) error {
	c.defaults()
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, c.Interval*3)
		res, err := Cycle(cctx, c)
		cancel()
		_ = Heartbeat(ctx, c.HeartbeatURL, err != nil)
		if onCycle != nil {
			onCycle(res, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// StatusLine renders one compact line per cycle for the terminal.
func StatusLine(r *CycleResult) string {
	if r == nil {
		return ""
	}
	if len(r.Stats) == 0 {
		return r.At.Local().Format("15:04") + "  no AI usage in window"
	}
	var parts []string
	var total float64
	for _, s := range r.Stats {
		total += s.PerHour
		line := fmt.Sprintf("%s ~$%.2f/h %.1frpm today~$%.2f", s.Scope, s.PerHour, s.RPM, s.Today)
		if s.FailedPct > 0 {
			line += fmt.Sprintf(" (%.0f%% failed)", s.FailedPct)
		}
		parts = append(parts, line)
	}
	return fmt.Sprintf("%s  total ~$%.2f/h · %s", r.At.Local().Format("15:04"), total, strings.Join(parts, " · "))
}
