package gcp

import (
	"context"
	"github.com/jhelbling/billfuse/internal/gcpfake"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAudit(t *testing.T) {
	srv := gcpfake.New(t)
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Token: "test", E: Endpoints{srv.URL, srv.URL, srv.URL, srv.URL, srv.URL}}
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	rep, err := Audit(context.Background(), c, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Severity{}
	for _, f := range rep.Findings {
		got[f.Code+"|"+f.Project+"|"+f.Resource] = f.Severity
	}
	want := map[string]Severity{
		"PROJECT_INVISIBLE|xx-miner-4821|":                                              Critical,
		"KEY_UNRESTRICTED_AI|prod-app|Android key (auto created by Firebase) (k-unres)": Critical,
		"KEY_AI_ACCESS|prod-app|backend (k-gem)":                                        High,
		"KEY_AI_ACCESS|prod-app|web (k-gem-web)":                                        Medium,
		"KEY_UNRESTRICTED_BILLABLE|staging|old test (k-stg)":                            High,
		"KEY_UNRESTRICTED_BILLABLE|staging|translator (k-tr)":                           High,
		"PROJECT_RECENT|new-thing|":                                                     Medium,
		"PROJECT_FOREIGN_ORG|other-org|":                                                High,
		"BA_DORMANT_OPEN||":                                                             Low,
	}
	for k, s := range want {
		if g, ok := got[k]; !ok || g != s {
			t.Errorf("finding %q: got %v (present=%v), want %v", k, g, ok, s)
		}
	}
	if _, ok := got["KEY_AI_ACCESS|prod-app|maps (k-maps)"]; ok {
		t.Error("maps-only key should not be flagged")
	}
	if rep.Findings[0].Severity != Critical {
		t.Error("findings not sorted by severity")
	}
	var stg, tr *KeyReport
	for _, k := range rep.Keys {
		switch k.ID {
		case "k-stg":
			stg = k
		case "k-tr":
			tr = k
		}
	}
	if stg == nil || tr == nil {
		t.Fatal("staging keys missing from report")
	}
	if tr.AppRestrict {
		t.Error("empty androidKeyRestrictions must not count as an app restriction")
	}
	if !stg.UsageKnown || stg.Requests != 0 {
		t.Errorf("k-stg should be known-unused, got %+v", stg)
	}
	if tr.Requests != 42 || tr.LastUsed.Format("2006-01-02") != "2026-10-17" || len(tr.UsedServices) != 1 {
		t.Errorf("k-tr usage wrong: %+v", tr)
	}
	for _, f := range rep.Findings {
		if f.Resource == "old test (k-stg)" && !strings.Contains(f.Fix, "api-keys delete k-stg --project staging") {
			t.Errorf("unused key should get delete fix, got %q", f.Fix)
		}
		if f.Resource == "translator (k-tr)" && !strings.Contains(f.Fix, "--api-target=service=translate.googleapis.com") {
			t.Errorf("used key should get restrict fix, got %q", f.Fix)
		}
	}
	// prod-app has no monitoring route -> usage unknown -> warning, but audit continues
	// new-thing has the API Keys API disabled -> no keys exist, so no noisy warning.
	for _, p := range rep.Projects {
		if p.ProjectID == "new-thing" && len(p.Warnings) > 0 {
			t.Errorf("unexpected warnings for new-thing: %v", p.Warnings)
		}
	}
}

func TestAuditNoBillingAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), Token: "x", E: Endpoints{srv.URL, srv.URL, srv.URL, srv.URL, srv.URL}}
	if _, err := Audit(context.Background(), c, Options{}); err == nil {
		t.Fatal("expected error when billing accounts cannot be listed and no --project given")
	}
}
