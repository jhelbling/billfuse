// Package gcpfake is a fake Google Cloud REST server used by tests and demos.
package gcpfake

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"
)

// New serves a scenario modelled on the incidents in the research:
//   - billing account AAA with own projects in org 1, a recent project, an
//     invisible project (foreign), a project from another org
//   - keys: unrestricted + Gemini on, restricted-to-Gemini without app restriction,
//     restricted-to-Gemini with referrer restriction, safe Maps-only key
//
// T is the subset of testing.TB the fake needs (also satisfied by the demo logger).
type T interface {
	Errorf(format string, args ...any)
}

func New(t T) *httptest.Server {
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	ts := func(d int) string { return now.AddDate(0, 0, -d).Format(time.RFC3339) }
	routes := map[string]any{
		"/v1/billingAccounts": map[string]any{"billingAccounts": []any{
			map[string]any{"name": "billingAccounts/AAA", "displayName": "Main", "open": true},
			map[string]any{"name": "billingAccounts/BBB", "displayName": "Old side project", "open": true},
		}},
		"/v1/billingAccounts/AAA/projects": map[string]any{"projectBillingInfo": []any{
			map[string]any{"projectId": "prod-app", "billingEnabled": true},
			map[string]any{"projectId": "new-thing", "billingEnabled": true},
			map[string]any{"projectId": "xx-miner-4821", "billingEnabled": true},
			map[string]any{"projectId": "other-org", "billingEnabled": true},
			map[string]any{"projectId": "staging", "billingEnabled": true},
		}},
		"/v1/billingAccounts/BBB/projects": map[string]any{"projectBillingInfo": []any{}},
		"/v3/projects/prod-app":            map[string]any{"projectId": "prod-app", "parent": "organizations/1", "createTime": ts(900)},
		"/v3/projects/staging":             map[string]any{"projectId": "staging", "parent": "organizations/1", "createTime": ts(500)},
		"/v3/projects/new-thing":           map[string]any{"projectId": "new-thing", "parent": "organizations/1", "createTime": ts(3)},
		"/v3/projects/other-org":           map[string]any{"projectId": "other-org", "parent": "organizations/999", "createTime": ts(400)},
		"/v1/projects/prod-app/services": map[string]any{"services": []any{
			map[string]any{"config": map[string]any{"name": "generativelanguage.googleapis.com"}},
			map[string]any{"config": map[string]any{"name": "apikeys.googleapis.com"}},
		}},
		"/v1/projects/staging/services": map[string]any{"services": []any{
			map[string]any{"config": map[string]any{"name": "apikeys.googleapis.com"}},
			map[string]any{"config": map[string]any{"name": "translate.googleapis.com"}},
		}},
		"/v1/projects/new-thing/services": map[string]any{},
		"/v1/projects/other-org/services": map[string]any{},
		"/v2/projects/prod-app/locations/global/keys": map[string]any{"keys": []any{
			map[string]any{"name": "projects/1/locations/global/keys/k-unres", "displayName": "Android key (auto created by Firebase)", "createTime": ts(3000)},
			map[string]any{"name": "projects/1/locations/global/keys/k-gem", "displayName": "backend",
				"restrictions": map[string]any{"apiTargets": []any{map[string]any{"service": "generativelanguage.googleapis.com"}}}},
			map[string]any{"name": "projects/1/locations/global/keys/k-gem-web", "displayName": "web",
				"restrictions": map[string]any{"browserKeyRestrictions": map[string]any{"allowedReferrers": []string{"https://app.example/*"}},
					"apiTargets": []any{map[string]any{"service": "generativelanguage.googleapis.com"}}}},
			map[string]any{"name": "projects/1/locations/global/keys/k-maps", "displayName": "maps",
				"restrictions": map[string]any{"apiTargets": []any{map[string]any{"service": "maps-backend.googleapis.com"}}}},
		}},
		"/v3/projects/staging/timeSeries": map[string]any{"timeSeries": []any{
			map[string]any{"resource": map[string]any{"labels": map[string]string{"credential_id": "apikey:uid-tr", "service": "translate.googleapis.com"}},
				"points": []any{
					map[string]any{"interval": map[string]any{"endTime": ts(2)}, "value": map[string]any{"int64Value": "40"}},
					map[string]any{"interval": map[string]any{"endTime": ts(10)}, "value": map[string]any{"int64Value": "2"}},
				}},
			map[string]any{"resource": map[string]any{"labels": map[string]string{"credential_id": "serviceaccount:123", "service": "translate.googleapis.com"}},
				"points": []any{map[string]any{"interval": map[string]any{"endTime": ts(1)}, "value": map[string]any{"int64Value": "999"}}}},
		}},
		"/v2/projects/staging/locations/global/keys": map[string]any{"keys": []any{
			map[string]any{"name": "projects/2/locations/global/keys/k-stg", "uid": "uid-stg", "displayName": "old test", "createTime": ts(2000)},
			map[string]any{"name": "projects/2/locations/global/keys/k-tr", "uid": "uid-tr", "displayName": "translator",
				"restrictions": map[string]any{"androidKeyRestrictions": map[string]any{}}},
		}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("non-GET request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test" {
			w.WriteHeader(401)
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"message":"The caller does not have permission"}}`))
			return
		}
		json.NewEncoder(w).Encode(body)
	}))
}
