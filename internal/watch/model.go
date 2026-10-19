// Package watch is the near-real-time spend monitor: it polls per-minute usage
// metrics (not billing), estimates $/hour, evaluates rules, alerts and - only
// with --act - trips a kill switch.
package watch

import (
	"context"
	"time"

	"github.com/jhelbling/billfuse/internal/sev"
)

// Sample is usage attributed to one (scope, region, service, model, credential) over a window.
type Sample struct {
	Cloud      string  `json:"cloud"` // gcp | aws
	Scope      string  `json:"scope"` // GCP project ID | AWS account ID
	Region     string  `json:"region,omitempty"`
	Service    string  `json:"service,omitempty"`
	Model      string  `json:"model,omitempty"`
	Credential string  `json:"credential,omitempty"`
	Requests   float64 `json:"requests"`
	Failed     float64 `json:"failed_requests,omitempty"` // non-2xx: not billed, but a probing signal
	InTok      float64 `json:"input_tokens"`
	OutTok     float64 `json:"output_tokens"`
	Cost       float64 `json:"est_cost_usd"`
	PriceKnown bool    `json:"price_known"`
}

// Collector reads usage for [start,end].
type Collector interface {
	Cloud() string
	Collect(ctx context.Context, start, end time.Time) ([]Sample, []string, error)
}

// Actor trips the kill switch for one scope. It must honour dryRun.
type Actor interface {
	Act(ctx context.Context, scope string, samples []Sample, dryRun bool) (string, error)
}

type Alert struct {
	Key      string       `json:"key"`
	Severity sev.Severity `json:"severity"`
	Cloud    string       `json:"cloud"`
	Scope    string       `json:"scope"`
	Title    string       `json:"title"`
	Detail   string       `json:"detail"`
	Trip     bool         `json:"trip"`     // eligible for the kill switch
	Resolved bool         `json:"resolved"` // a previously firing threshold cleared
}

type Limits struct {
	MaxHourly   float64 // est. $/hour per scope -> CRITICAL (trip)
	MaxDaily    float64 // est. $ since 00:00 UTC per scope -> CRITICAL (trip)
	MaxRPM      float64 // AI requests per minute per scope -> HIGH
	SpikeFactor float64 // rate > factor x baseline -> HIGH
	SpikeFloor  float64 // ignore spikes below this $/hour
	Warmup      int     // cycles before spike / new-X rules fire
	Expected    map[string]bool
}
