package watch

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jhelbling/billfuse/internal/sev"
)

// ScopeStat is the per-scope rollup of one cycle.
type ScopeStat struct {
	Cloud      string   `json:"cloud"`
	Scope      string   `json:"scope"`
	PerHour    float64  `json:"est_usd_per_hour"`
	RPM        float64  `json:"requests_per_minute"`
	FailedPct  float64  `json:"failed_pct,omitempty"`
	Today      float64  `json:"est_usd_today"`
	Top        string   `json:"top,omitempty"` // biggest contributor in the window
	Unpriced   []string `json:"unpriced_models,omitempty"`
	Regions    []string `json:"regions,omitempty"`
	windowCost float64
}

func Rollup(recent, today []Sample, windowMin float64) map[string]*ScopeStat {
	out := map[string]*ScopeStat{}
	get := func(s Sample) *ScopeStat {
		k := s.Cloud + "|" + s.Scope
		st := out[k]
		if st == nil {
			st = &ScopeStat{Cloud: s.Cloud, Scope: s.Scope}
			out[k] = st
		}
		return st
	}
	top := map[string]map[string]float64{}
	failed := map[string]float64{}
	reqs := map[string]float64{}
	for _, s := range recent {
		st := get(s)
		failed[s.Cloud+"|"+s.Scope] += s.Failed
		reqs[s.Cloud+"|"+s.Scope] += s.Requests
		st.windowCost += s.Cost
		st.RPM += s.Requests / windowMin
		if s.Region != "" && (s.Requests > 0 || s.InTok > 0) && !contains(st.Regions, s.Region) {
			st.Regions = append(st.Regions, s.Region)
		}
		if !s.PriceKnown && s.Model != "" && !contains(st.Unpriced, s.Model) {
			st.Unpriced = append(st.Unpriced, s.Model)
		}
		label := strings.Trim(strings.Join([]string{s.Region, s.Model, short(s.Service), s.Credential}, " "), " ")
		k := s.Cloud + "|" + s.Scope
		if top[k] == nil {
			top[k] = map[string]float64{}
		}
		top[k][label] += s.Cost
	}
	for _, s := range today {
		get(s).Today += s.Cost
	}
	for k, st := range out {
		st.PerHour = st.windowCost * 60 / windowMin
		if reqs[k] > 0 {
			st.FailedPct = 100 * failed[k] / reqs[k]
		}
		best, bv := "", 0.0
		for l, v := range top[k] {
			if v > bv {
				best, bv = l, v
			}
		}
		if bv > 0 {
			st.Top = fmt.Sprintf("%s ~$%.2f/h", best, bv*60/windowMin)
		}
		sort.Strings(st.Regions)
	}
	return out
}

func short(svc string) string { return strings.TrimSuffix(svc, ".googleapis.com") }

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Evaluate applies the rules, updates baselines/seen sets in st, and returns alerts.
func Evaluate(stats map[string]*ScopeStat, recent []Sample, lim Limits, st *State) []Alert {
	var alerts []Alert
	warm := st.Cycles >= lim.Warmup
	fire := func(a Alert, threshold bool) {
		if threshold {
			st.Active[a.Key] = true
		}
		alerts = append(alerts, a)
	}
	firing := map[string]bool{}

	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := stats[k]
		where := s.Cloud + " " + s.Scope
		if lim.MaxHourly > 0 && s.PerHour > lim.MaxHourly {
			key := k + "|hourly"
			firing[key] = true
			fire(Alert{Key: key, Severity: sev.Critical, Cloud: s.Cloud, Scope: s.Scope, Trip: true,
				Title:  fmt.Sprintf("%s burning ~$%.2f/h (limit $%.0f/h)", where, s.PerHour, lim.MaxHourly),
				Detail: detail(s)}, true)
		}
		if lim.MaxDaily > 0 && s.Today > lim.MaxDaily {
			key := k + "|daily"
			firing[key] = true
			fire(Alert{Key: key, Severity: sev.Critical, Cloud: s.Cloud, Scope: s.Scope, Trip: true,
				Title:  fmt.Sprintf("%s spent ~$%.2f today (limit $%.0f/day)", where, s.Today, lim.MaxDaily),
				Detail: detail(s)}, true)
		}
		if lim.MaxRPM > 0 && s.RPM > lim.MaxRPM {
			key := k + "|rpm"
			firing[key] = true
			fire(Alert{Key: key, Severity: sev.High, Cloud: s.Cloud, Scope: s.Scope,
				Title:  fmt.Sprintf("%s at %.0f AI requests/min (limit %.0f)", where, s.RPM, lim.MaxRPM),
				Detail: detail(s)}, true)
		}
		base, hasBase := st.Baseline[k]
		if warm && hasBase && lim.SpikeFactor > 0 && s.PerHour > lim.SpikeFloor && s.PerHour > lim.SpikeFactor*base {
			key := k + "|spike"
			firing[key] = true
			fire(Alert{Key: key, Severity: sev.High, Cloud: s.Cloud, Scope: s.Scope,
				Title:  fmt.Sprintf("%s spend spiked to ~$%.2f/h (%.0fx its usual ~$%.2f/h)", where, s.PerHour, s.PerHour/maxf(base, 0.01), base),
				Detail: detail(s)}, true)
		} else {
			// learn only from non-spiking cycles so an attack doesn't become the new normal
			if !hasBase {
				st.Baseline[k] = s.PerHour
			} else {
				st.Baseline[k] = 0.9*base + 0.1*s.PerHour
			}
		}
		if len(s.Unpriced) > 0 && s.PerHour > 0 {
			key := k + "|unpriced|" + strings.Join(s.Unpriced, ",")
			if _, seen := st.Seen[key]; !seen {
				st.Seen[key] = nowFn()
				alerts = append(alerts, Alert{Key: key, Severity: sev.Low, Cloud: s.Cloud, Scope: s.Scope,
					Title:  where + ": no price for " + strings.Join(s.Unpriced, ", ") + " - estimating at the conservative default",
					Detail: "add it to a --prices file for accurate $/h"})
			}
		}
	}

	// New region / model / credential with traffic.
	for _, smp := range recent {
		if smp.Requests <= 0 && smp.InTok <= 0 {
			continue
		}
		check := func(kind, val string) {
			if val == "" {
				return
			}
			key := smp.Cloud + "|" + smp.Scope + "|" + kind + "|" + val
			if _, ok := st.Seen[key]; ok {
				return
			}
			st.Seen[key] = nowFn()
			if !warm {
				return // first cycles only learn
			}
			sv := sev.Medium
			title := fmt.Sprintf("%s %s: first traffic from new %s %s", smp.Cloud, smp.Scope, kind, val)
			if kind == "region" && len(lim.Expected) > 0 && !lim.Expected[val] {
				sv = sev.High
				title = fmt.Sprintf("%s %s: AI usage in UNEXPECTED region %s", smp.Cloud, smp.Scope, val)
			}
			alerts = append(alerts, Alert{Key: key, Severity: sv, Cloud: smp.Cloud, Scope: smp.Scope, Title: title,
				Detail: fmt.Sprintf("%s %s · %.0f requests, %.0f in / %.0f out tokens in the window", smp.Model, short(smp.Service), smp.Requests, smp.InTok, smp.OutTok)})
		}
		check("region", smp.Region)
		check("model", smp.Model)
		check("credential", smp.Credential)
	}

	// Resolutions for thresholds that stopped firing.
	for key := range st.Active {
		if firing[key] {
			continue
		}
		delete(st.Active, key)
		parts := strings.SplitN(key, "|", 3)
		if len(parts) < 3 {
			continue
		}
		alerts = append(alerts, Alert{Key: key, Severity: sev.Info, Cloud: parts[0], Scope: parts[1], Resolved: true,
			Title: fmt.Sprintf("%s %s: %s alert resolved", parts[0], parts[1], parts[2])})
	}
	st.Cycles++
	return alerts
}

func detail(s *ScopeStat) string {
	d := fmt.Sprintf("~$%.2f/h · %.1f req/min · ~$%.2f today", s.PerHour, s.RPM, s.Today)
	if s.FailedPct > 0 {
		d += fmt.Sprintf(" · %.0f%% of requests failed (not billed)", s.FailedPct)
	}
	if s.Top != "" {
		d += " · top: " + s.Top
	}
	if len(s.Regions) > 0 {
		d += " · regions: " + strings.Join(s.Regions, ", ")
	}
	return d + " (estimates from usage metrics, not your bill)"
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
