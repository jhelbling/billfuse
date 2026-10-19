package watch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jhelbling/billfuse/internal/gcp"
)

func TestGCPCollectorAndActor(t *testing.T) {
	var disabled []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			disabled = append(disabled, r.URL.Path)
			w.Write([]byte(`{}`))
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/billingAccounts/AAA/projects"):
			w.Write([]byte(`{"projectBillingInfo":[{"projectId":"app","billingEnabled":true},{"projectId":"off","billingEnabled":false}]}`))
		case r.URL.Path == "/v3/projects/app/timeSeries":
			f := r.URL.Query().Get("filter")
			if strings.Contains(f, "token_count") {
				json.NewEncoder(w).Encode(map[string]any{"timeSeries": []any{
					map[string]any{"resource": map[string]any{"labels": map[string]string{"model_user_id": "gemini-2.5-pro", "location": "us-central1"}},
						"metric": map[string]any{"labels": map[string]string{"type": "input"}}, "points": []any{map[string]any{"value": map[string]any{"int64Value": "2000000"}}}},
					map[string]any{"resource": map[string]any{"labels": map[string]string{"model_user_id": "gemini-2.5-pro", "location": "us-central1"}},
						"metric": map[string]any{"labels": map[string]string{"type": "output"}}, "points": []any{map[string]any{"value": map[string]any{"int64Value": "100000"}}}},
				}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"timeSeries": []any{
				map[string]any{"resource": map[string]any{"labels": map[string]string{"service": "generativelanguage.googleapis.com", "credential_id": "apikey:abc"}},
					"metric": map[string]any{"labels": map[string]string{"response_code_class": "2xx"}},
					"points": []any{map[string]any{"value": map[string]any{"int64Value": "500"}}}},
				map[string]any{"resource": map[string]any{"labels": map[string]string{"service": "generativelanguage.googleapis.com", "credential_id": "apikey:abc"}},
					"metric": map[string]any{"labels": map[string]string{"response_code_class": "4xx"}},
					"points": []any{map[string]any{"value": map[string]any{"int64Value": "300"}}}},
				map[string]any{"resource": map[string]any{"labels": map[string]string{"service": "generativelanguage.googleapis.com", "credential_id": "apikey:abc", "method": "google.ai.generativelanguage.v1beta.ModelService.ListModels"}},
					"metric": map[string]any{"labels": map[string]string{"response_code_class": "2xx"}},
					"points": []any{map[string]any{"value": map[string]any{"int64Value": "1000"}}}},
				map[string]any{"resource": map[string]any{"labels": map[string]string{"service": "aiplatform.googleapis.com", "credential_id": "serviceaccount:123"}},
					"points": []any{map[string]any{"value": map[string]any{"int64Value": "40"}}}},
			}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := &gcp.Client{HTTP: srv.Client(), Token: "t", E: gcp.Endpoints{Billing: srv.URL, ResourceManager: srv.URL, ServiceUsage: srv.URL, APIKeys: srv.URL, Monitoring: srv.URL}}
	col := &GCPCollector{C: c, BillingAccounts: []string{"AAA"}, Pricing: DefaultPricing()}
	end := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	s, warns, err := col.Collect(context.Background(), end.Add(-10*time.Minute), end)
	if err != nil || len(warns) != 0 {
		t.Fatalf("err=%v warns=%v", err, warns)
	}
	var cost float64
	var gem, vtx bool
	for _, x := range s {
		cost += x.Cost
		if x.Model == "gemini-api" && x.Requests == 1800 && x.Failed == 300 && x.Credential == "key:abc" {
			gem = true
		}
		if x.Model == "gemini-2.5-pro" && x.InTok == 2e6 && x.OutTok == 1e5 {
			vtx = true
		}
	}
	// gemini api: 500 req x $0.01 = 5; vertex: 2Mx1.25 + 0.1Mx10 = 2.5+1 = 3.5; vertex requests not double-counted.
	if !gem || !vtx || cost < 8.49 || cost > 8.51 {
		t.Errorf("gem=%v vtx=%v cost=%v samples=%+v", gem, vtx, cost, s)
	}
	out, err := GCPActor{C: c}.Act(context.Background(), "app", s, false)
	if err != nil || len(disabled) != 2 || !strings.Contains(out, "undo: gcloud services enable") {
		t.Errorf("act out=%q disabled=%v err=%v", out, disabled, err)
	}
}
