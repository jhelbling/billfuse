package watch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jhelbling/billfuse/internal/gcp"
)

// GCPCollector reads Gemini API / Vertex AI usage from Cloud Monitoring.
//   - request counts per service & API key: serviceruntime.googleapis.com/api/request_count
//   - Vertex token counts per model:        aiplatform.googleapis.com/publisher/online_serving/token_count
//
// The Gemini Developer API exposes no token metric, so its cost is estimated per request.
type GCPCollector struct {
	C               *gcp.Client
	Projects        []string // explicit
	BillingAccounts []string // discover billed projects on these (refreshed hourly)
	Pricing         Pricing

	mu         sync.Mutex
	discovered []string
	lastDisc   time.Time
}

func (g *GCPCollector) Cloud() string { return "gcp" }

func (g *GCPCollector) projects(ctx context.Context) ([]string, []string) {
	var warns []string
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.BillingAccounts) > 0 && time.Since(g.lastDisc) > time.Hour {
		var found []string
		for _, ba := range g.BillingAccounts {
			ps, err := g.C.ListBillingProjects(ctx, strings.TrimPrefix(ba, "billingAccounts/"))
			if err != nil {
				warns = append(warns, "billing account "+ba+": "+err.Error())
				continue
			}
			for _, p := range ps {
				if p.BillingEnabled {
					found = append(found, p.ProjectID)
				}
			}
		}
		if len(found) > 0 || len(warns) == 0 {
			g.discovered, g.lastDisc = found, time.Now()
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range append(append([]string{}, g.Projects...), g.discovered...) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, warns
}

const reqFilter = `metric.type="serviceruntime.googleapis.com/api/request_count" AND (resource.label.service="generativelanguage.googleapis.com" OR resource.label.service="aiplatform.googleapis.com")`
const tokFilter = `metric.type="aiplatform.googleapis.com/publisher/online_serving/token_count"`

func (g *GCPCollector) Collect(ctx context.Context, start, end time.Time) ([]Sample, []string, error) {
	projects, warns := g.projects(ctx)
	if len(projects) == 0 {
		return nil, warns, fmt.Errorf("no projects to watch (pass --project or --billing-account)")
	}
	var mu sync.Mutex
	var out []Sample
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, p := range projects {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			s, w := g.project(ctx, p, start, end)
			mu.Lock()
			out = append(out, s...)
			warns = append(warns, w...)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return out, warns, nil
}

func (g *GCPCollector) project(ctx context.Context, p string, start, end time.Time) ([]Sample, []string) {
	var warns []string
	var out []Sample

	// Vertex tokens per model (empty series if never used - not an error).
	toks, err := g.C.SumByLabels(ctx, p, tokFilter, []string{"resource.label.model_user_id", "resource.label.location", "metric.label.type"}, start, end)
	if err != nil && !gcp.IsForbiddenOrNotFound(err) && !strings.Contains(err.Error(), "HTTP 400") {
		warns = append(warns, p+": vertex token metric: "+err.Error())
	}
	type mk struct{ model, loc string }
	tok := map[mk]*Sample{}
	for _, s := range toks {
		k := mk{s.Labels["model_user_id"], s.Labels["location"]}
		smp := tok[k]
		if smp == nil {
			smp = &Sample{Cloud: "gcp", Scope: p, Region: k.loc, Service: "aiplatform.googleapis.com", Model: k.model}
			tok[k] = smp
		}
		if strings.Contains(strings.ToLower(s.Labels["type"]), "output") {
			smp.OutTok += s.Sum
		} else {
			smp.InTok += s.Sum
		}
	}
	for _, s := range tok {
		s.Cost, s.PriceKnown = g.Pricing.TokenCost(s.Model, s.InTok, s.OutTok)
		out = append(out, *s)
	}

	// Requests per service & credential.
	reqs, err := g.C.SumByLabels(ctx, p, reqFilter, []string{"resource.label.service", "resource.label.credential_id", "resource.label.method", "metric.label.response_code_class"}, start, end)
	if err != nil {
		warns = append(warns, p+": request metric (needs roles/monitoring.viewer): "+err.Error())
		return out, warns
	}
	// All requests count toward rate/rpm (probing with a stolen key shows up as 4xx),
	// but only successful (2xx) calls are billed.
	type rk struct{ svc, cred string }
	agg := map[rk]*Sample{}
	for _, s := range reqs {
		k := rk{s.Labels["service"], credLabel(s.Labels["credential_id"])}
		smp := agg[k]
		if smp == nil {
			smp = &Sample{Cloud: "gcp", Scope: p, Service: k.svc, Credential: k.cred, PriceKnown: true}
			agg[k] = smp
		}
		smp.Requests += s.Sum
		if cls := s.Labels["response_code_class"]; cls != "" && cls != "2xx" {
			smp.Failed += s.Sum
			continue
		}
		if !billableMethod(s.Labels["method"]) {
			continue // ListModels, GetModel, CountTokens, file ops ... are free
		}
		switch k.svc {
		case "generativelanguage.googleapis.com":
			smp.Cost += s.Sum / 1000 * g.Pricing.GeminiPerKReq
		case "aiplatform.googleapis.com":
			if len(tok) == 0 { // no token data: fall back to per-request estimate
				smp.Cost += s.Sum / 1000 * g.Pricing.VertexPerKReq
			}
		}
	}
	for _, smp := range agg {
		if smp.Service == "generativelanguage.googleapis.com" {
			smp.Model = "gemini-api"
		}
		out = append(out, *smp)
	}
	return out, warns
}

func credLabel(c string) string {
	switch {
	case strings.HasPrefix(c, "apikey:"):
		return "key:" + c[len("apikey:"):]
	case strings.HasPrefix(c, "serviceaccount:"):
		return "sa:" + c[len("serviceaccount:"):]
	}
	return c
}

// GCPActor disables the AI APIs that had traffic on the tripped project.
// Reversible: gcloud services enable <service> --project <p>.
type GCPActor struct{ C *gcp.Client }

func (a GCPActor) Act(ctx context.Context, scope string, samples []Sample, dryRun bool) (string, error) {
	svcs := map[string]bool{}
	for _, s := range samples {
		if s.Scope == scope && s.Service != "" && (s.Requests > 0 || s.InTok > 0) {
			svcs[s.Service] = true
		}
	}
	if len(svcs) == 0 {
		svcs["generativelanguage.googleapis.com"] = true
		svcs["aiplatform.googleapis.com"] = true
	}
	var done []string
	for svc := range svcs {
		cmd := fmt.Sprintf("gcloud services disable %s --project %s", svc, scope)
		if dryRun {
			done = append(done, "[dry-run] would run: "+cmd)
			continue
		}
		if err := a.C.DisableService(ctx, scope, svc); err != nil {
			return strings.Join(done, "\n"), fmt.Errorf("%s: %w", cmd, err)
		}
		done = append(done, "DONE: "+cmd+"  (undo: gcloud services enable "+svc+" --project "+scope+")")
	}
	return strings.Join(done, "\n"), nil
}

// billableMethod: only inference calls cost money. Unknown/missing method -> billable (conservative).
func billableMethod(m string) bool {
	if m == "" {
		return true
	}
	m = strings.ToLower(m)
	for _, k := range []string{"generate", "embed", "predict", "batch"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}
