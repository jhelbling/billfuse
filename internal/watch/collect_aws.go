package watch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	awsc "github.com/jhelbling/billfuse/internal/aws"
)

// AWSCollector reads Bedrock usage from CloudWatch (AWS/Bedrock, 1-minute metrics) in every region.
type AWSCollector struct {
	C       *awsc.Client
	Account string
	Regions []string
	Pricing Pricing

	mu         sync.Mutex
	models     map[string][]string // region -> model IDs seen in ListMetrics
	dead       map[string]bool     // regions that never answer (opt-in disabled)
	lastModels time.Time
}

func (a *AWSCollector) Cloud() string { return "aws" }

func (a *AWSCollector) refreshModels(ctx context.Context) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.models != nil && time.Since(a.lastModels) < 10*time.Minute {
		return nil
	}
	if a.dead == nil {
		a.dead = map[string]bool{}
	}
	var warns []string
	models := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range a.Regions {
		if a.dead[r] {
			continue
		}
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			ms, err := a.C.BedrockModelsWithTraffic(rctx, r)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				if len(ms) > 0 {
					models[r] = ms
				}
			case awsc.IsRegionDisabled(err) || rctx.Err() != nil:
				a.dead[r] = true
			default:
				warns = append(warns, r+": cloudwatch:ListMetrics: "+err.Error())
			}
		}(r)
	}
	wg.Wait()
	a.models, a.lastModels = models, time.Now()
	return warns
}

func (a *AWSCollector) Collect(ctx context.Context, start, end time.Time) ([]Sample, []string, error) {
	warns := a.refreshModels(ctx)
	a.mu.Lock()
	models := a.models
	a.mu.Unlock()
	var out []Sample
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for region, ms := range models {
		for _, m := range ms {
			wg.Add(1)
			sem <- struct{}{}
			go func(region, m string) {
				defer wg.Done()
				defer func() { <-sem }()
				s := Sample{Cloud: "aws", Scope: a.Account, Region: region, Service: "bedrock", Model: m}
				var err error
				if s.Requests, err = a.C.BedrockWindowSum(ctx, region, "Invocations", m, start, end); err == nil {
					if s.InTok, err = a.C.BedrockWindowSum(ctx, region, "InputTokenCount", m, start, end); err == nil {
						s.OutTok, err = a.C.BedrockWindowSum(ctx, region, "OutputTokenCount", m, start, end)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					warns = append(warns, fmt.Sprintf("%s %s: %v", region, m, err))
					return
				}
				if s.Requests == 0 && s.InTok == 0 {
					return
				}
				s.Cost, s.PriceKnown = a.Pricing.TokenCost(m, s.InTok, s.OutTok)
				out = append(out, s)
			}(region, m)
		}
	}
	wg.Wait()
	return out, warns, nil
}

// AWSActor attaches an inline Deny bedrock:* policy to the configured principals.
// CloudWatch can't tell which principal is calling, so you choose the blast radius
// up front (e.g. "role:gitlab-runner,user:ci-bot"). Undo: delete the
// billfuse-deny-bedrock inline policy.
type AWSActor struct {
	C       *awsc.Client
	Targets []string // "role:NAME" | "user:NAME"
}

func (a AWSActor) Act(ctx context.Context, scope string, _ []Sample, dryRun bool) (string, error) {
	if len(a.Targets) == 0 {
		return "no --act-aws-deny targets configured: alert only. Fastest manual stop: an SCP or permissions boundary denying bedrock:*", nil
	}
	var done []string
	for _, t := range a.Targets {
		kind, name, ok := strings.Cut(t, ":")
		if !ok || (kind != "role" && kind != "user") {
			done = append(done, "skipped bad target "+t+" (use role:NAME or user:NAME)")
			continue
		}
		undo := fmt.Sprintf("aws iam delete-%s-policy --%s-name %s --policy-name %s", kind, kind, name, awsc.DenyBedrockPolicyName)
		if dryRun {
			done = append(done, fmt.Sprintf("[dry-run] would attach Deny bedrock:* to %s %s", kind, name))
			continue
		}
		if err := a.C.PutDenyBedrock(ctx, kind, name); err != nil {
			return strings.Join(done, "\n"), fmt.Errorf("deny %s %s: %w", kind, name, err)
		}
		done = append(done, fmt.Sprintf("DONE: Deny bedrock:* attached to %s %s  (undo: %s)", kind, name, undo))
	}
	return strings.Join(done, "\n"), nil
}
