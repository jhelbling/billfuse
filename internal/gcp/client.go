// Package gcp holds a tiny, dependency-free, read-only REST client for the
// handful of Google Cloud APIs the audit needs.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Endpoints lets tests point the client at a fake server.
type Endpoints struct {
	Billing         string // https://cloudbilling.googleapis.com
	ResourceManager string // https://cloudresourcemanager.googleapis.com
	ServiceUsage    string // https://serviceusage.googleapis.com
	APIKeys         string // https://apikeys.googleapis.com
	Monitoring      string // https://monitoring.googleapis.com
}

func DefaultEndpoints() Endpoints {
	return Endpoints{
		Billing:         "https://cloudbilling.googleapis.com",
		ResourceManager: "https://cloudresourcemanager.googleapis.com",
		ServiceUsage:    "https://serviceusage.googleapis.com",
		APIKeys:         "https://apikeys.googleapis.com",
		Monitoring:      "https://monitoring.googleapis.com",
	}
}

type Client struct {
	HTTP      *http.Client
	Token     string
	E         Endpoints
	QuotaProj string // optional x-goog-user-project header
}

// APIError carries the HTTP status so callers can tell "forbidden" from real failures.
type APIError struct {
	Status  int
	Message string
	URL     string
}

func (e *APIError) Error() string {
	u := e.URL
	if i := strings.Index(u, "?"); i >= 0 {
		u = u[:i]
	}
	return fmt.Sprintf("HTTP %d from %s: %s", e.Status, u, e.Message)
}

func IsForbiddenOrNotFound(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.Status == 403 || ae.Status == 404
	}
	return false
}

// get performs a GET (the client never issues anything else - read-only by construction).
func (c *Client) get(ctx context.Context, base, path string, q url.Values, out any) error {
	u := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("User-Agent", "billfuse-audit/0.1")
		if c.QuotaProj != "" {
			req.Header.Set("x-goog-user-project", c.QuotaProj)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = &APIError{resp.StatusCode, errMsg(body), u}
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			return &APIError{resp.StatusCode, errMsg(body), u}
		}
		return json.Unmarshal(body, out)
	}
	return lastErr
}

func errMsg(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// ---- Cloud Billing ----

type BillingAccount struct {
	Name        string `json:"name"` // billingAccounts/XXXXXX-XXXXXX-XXXXXX
	DisplayName string `json:"displayName"`
	Open        bool   `json:"open"`
}

func (c *Client) ListBillingAccounts(ctx context.Context) ([]BillingAccount, error) {
	var all []BillingAccount
	tok := ""
	for {
		var r struct {
			BillingAccounts []BillingAccount `json:"billingAccounts"`
			NextPageToken   string           `json:"nextPageToken"`
		}
		q := url.Values{"pageSize": {"100"}}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		if err := c.get(ctx, c.E.Billing, "/v1/billingAccounts", q, &r); err != nil {
			return nil, err
		}
		all = append(all, r.BillingAccounts...)
		if r.NextPageToken == "" {
			return all, nil
		}
		tok = r.NextPageToken
	}
}

func (c *Client) GetBillingAccount(ctx context.Context, id string) (BillingAccount, error) {
	var b BillingAccount
	err := c.get(ctx, c.E.Billing, "/v1/billingAccounts/"+id, nil, &b)
	return b, err
}

type ProjectBillingInfo struct {
	ProjectID      string `json:"projectId"`
	BillingEnabled bool   `json:"billingEnabled"`
}

func (c *Client) ListBillingProjects(ctx context.Context, accountID string) ([]ProjectBillingInfo, error) {
	var all []ProjectBillingInfo
	tok := ""
	for {
		var r struct {
			ProjectBillingInfo []ProjectBillingInfo `json:"projectBillingInfo"`
			NextPageToken      string               `json:"nextPageToken"`
		}
		q := url.Values{"pageSize": {"100"}}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		if err := c.get(ctx, c.E.Billing, "/v1/billingAccounts/"+accountID+"/projects", q, &r); err != nil {
			return nil, err
		}
		all = append(all, r.ProjectBillingInfo...)
		if r.NextPageToken == "" {
			return all, nil
		}
		tok = r.NextPageToken
	}
}

// ---- Resource Manager ----

type Project struct {
	Name        string    `json:"name"` // projects/123
	ProjectID   string    `json:"projectId"`
	DisplayName string    `json:"displayName"`
	Parent      string    `json:"parent"` // organizations/1 | folders/2 | ""
	State       string    `json:"state"`
	CreateTime  time.Time `json:"createTime"`
}

func (c *Client) GetProject(ctx context.Context, projectID string) (Project, error) {
	var p Project
	err := c.get(ctx, c.E.ResourceManager, "/v3/projects/"+projectID, nil, &p)
	return p, err
}

// ---- Service Usage ----

func (c *Client) EnabledServices(ctx context.Context, projectID string) (map[string]bool, error) {
	out := map[string]bool{}
	tok := ""
	for {
		var r struct {
			Services []struct {
				Config struct {
					Name string `json:"name"`
				} `json:"config"`
			} `json:"services"`
			NextPageToken string `json:"nextPageToken"`
		}
		q := url.Values{"filter": {"state:ENABLED"}, "pageSize": {"200"}}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		if err := c.get(ctx, c.E.ServiceUsage, "/v1/projects/"+projectID+"/services", q, &r); err != nil {
			return nil, err
		}
		for _, s := range r.Services {
			out[s.Config.Name] = true
		}
		if r.NextPageToken == "" {
			return out, nil
		}
		tok = r.NextPageToken
	}
}

// ---- API Keys ----

type APIKey struct {
	Name         string    `json:"name"` // projects/123/locations/global/keys/abc
	UID          string    `json:"uid"`
	DisplayName  string    `json:"displayName"`
	CreateTime   time.Time `json:"createTime"`
	Restrictions *struct {
		BrowserKeyRestrictions *struct {
			AllowedReferrers []string `json:"allowedReferrers"`
		} `json:"browserKeyRestrictions"`
		ServerKeyRestrictions *struct {
			AllowedIPs []string `json:"allowedIps"`
		} `json:"serverKeyRestrictions"`
		AndroidKeyRestrictions *struct {
			AllowedApplications []any `json:"allowedApplications"`
		} `json:"androidKeyRestrictions"`
		IOSKeyRestrictions *struct {
			AllowedBundleIDs []string `json:"allowedBundleIds"`
		} `json:"iosKeyRestrictions"`
		APITargets []struct {
			Service string   `json:"service"`
			Methods []string `json:"methods"`
		} `json:"apiTargets"`
	} `json:"restrictions"`
}

func (c *Client) ListAPIKeys(ctx context.Context, projectID string) ([]APIKey, error) {
	var all []APIKey
	tok := ""
	for {
		var r struct {
			Keys          []APIKey `json:"keys"`
			NextPageToken string   `json:"nextPageToken"`
		}
		q := url.Values{"pageSize": {"300"}}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		if err := c.get(ctx, c.E.APIKeys, "/v2/projects/"+projectID+"/locations/global/keys", q, &r); err != nil {
			return nil, err
		}
		all = append(all, r.Keys...)
		if r.NextPageToken == "" {
			return all, nil
		}
		tok = r.NextPageToken
	}
}

// ---- Cloud Monitoring: per-credential API usage ----

// KeyUsage is API traffic attributed to one API key over the query window.
type KeyUsage struct {
	Requests int64            `json:"requests"`
	LastUsed time.Time        `json:"last_used,omitempty"` // end of the last day with traffic
	Services map[string]int64 `json:"services"`
}

// KeyUsageByUID returns usage keyed by API key UID, from
// serviceruntime.googleapis.com/api/request_count (resource label credential_id = "apikey:<uid>").
func (c *Client) KeyUsageByUID(ctx context.Context, projectID string, start, end time.Time) (map[string]*KeyUsage, error) {
	out := map[string]*KeyUsage{}
	tok := ""
	for {
		q := url.Values{
			"filter":                         {`metric.type="serviceruntime.googleapis.com/api/request_count"`},
			"interval.startTime":             {start.UTC().Format(time.RFC3339)},
			"interval.endTime":               {end.UTC().Format(time.RFC3339)},
			"aggregation.alignmentPeriod":    {"86400s"},
			"aggregation.perSeriesAligner":   {"ALIGN_SUM"},
			"aggregation.crossSeriesReducer": {"REDUCE_SUM"},
			"aggregation.groupByFields":      {"resource.label.credential_id", "resource.label.service"},
			"pageSize":                       {"1000"},
		}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		var r struct {
			TimeSeries []struct {
				Resource struct {
					Labels map[string]string `json:"labels"`
				} `json:"resource"`
				Points []struct {
					Interval struct {
						EndTime time.Time `json:"endTime"`
					} `json:"interval"`
					Value struct {
						Int64Value json.Number `json:"int64Value"`
					} `json:"value"`
				} `json:"points"`
			} `json:"timeSeries"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.get(ctx, c.E.Monitoring, "/v3/projects/"+projectID+"/timeSeries", q, &r); err != nil {
			return nil, err
		}
		for _, ts := range r.TimeSeries {
			cred := ts.Resource.Labels["credential_id"]
			uid := strings.TrimPrefix(cred, "apikey:")
			svc := ts.Resource.Labels["service"]
			if uid == "" || uid == cred {
				continue
			}
			u := out[uid]
			if u == nil {
				u = &KeyUsage{Services: map[string]int64{}}
				out[uid] = u
			}
			for _, p := range ts.Points {
				n, _ := p.Value.Int64Value.Int64()
				if n <= 0 {
					continue
				}
				u.Requests += n
				u.Services[svc] += n
				if p.Interval.EndTime.After(u.LastUsed) {
					u.LastUsed = p.Interval.EndTime
				}
			}
		}
		if r.NextPageToken == "" {
			return out, nil
		}
		tok = r.NextPageToken
	}
}

// SeriesSum is one aggregated time series: its labels (resource + metric) and the summed value.
type SeriesSum struct {
	Labels map[string]string
	Sum    float64
}

// SumByLabels sums a DELTA metric over [start,end], grouped by the given label fields
// (e.g. "resource.label.service"). Labels in the result are keyed by short name ("service").
func (c *Client) SumByLabels(ctx context.Context, projectID, filter string, groupBy []string, start, end time.Time) ([]SeriesSum, error) {
	secs := int(end.Sub(start).Seconds())
	if secs < 60 {
		secs = 60
	}
	var out []SeriesSum
	tok := ""
	for {
		q := url.Values{
			"filter":                         {filter},
			"interval.startTime":             {start.UTC().Format(time.RFC3339)},
			"interval.endTime":               {end.UTC().Format(time.RFC3339)},
			"aggregation.alignmentPeriod":    {fmt.Sprintf("%ds", secs)},
			"aggregation.perSeriesAligner":   {"ALIGN_SUM"},
			"aggregation.crossSeriesReducer": {"REDUCE_SUM"},
			"aggregation.groupByFields":      groupBy,
			"pageSize":                       {"1000"},
		}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		var r struct {
			TimeSeries []struct {
				Metric   struct{ Labels map[string]string } `json:"metric"`
				Resource struct{ Labels map[string]string } `json:"resource"`
				Points   []struct {
					Value struct {
						Int64Value  json.Number `json:"int64Value"`
						DoubleValue *float64    `json:"doubleValue"`
					} `json:"value"`
				} `json:"points"`
			} `json:"timeSeries"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.get(ctx, c.E.Monitoring, "/v3/projects/"+projectID+"/timeSeries", q, &r); err != nil {
			return nil, err
		}
		for _, ts := range r.TimeSeries {
			s := SeriesSum{Labels: map[string]string{}}
			for k, v := range ts.Resource.Labels {
				s.Labels[k] = v
			}
			for k, v := range ts.Metric.Labels {
				s.Labels[k] = v
			}
			for _, p := range ts.Points {
				if p.Value.DoubleValue != nil {
					s.Sum += *p.Value.DoubleValue
				} else if n, err := p.Value.Int64Value.Float64(); err == nil {
					s.Sum += n
				}
			}
			out = append(out, s)
		}
		if r.NextPageToken == "" {
			return out, nil
		}
		tok = r.NextPageToken
	}
}

// ---------- Kill-switch writes (used only by `watch --act`) ----------

// DisableService turns off one API on a project (reversible: gcloud services enable <svc>).
func (c *Client) DisableService(ctx context.Context, projectID, service string) error {
	body := `{"disableDependentServices":false,"checkIfServiceHasUsage":"SKIP"}`
	return c.post(ctx, c.E.ServiceUsage, "/v1/projects/"+projectID+"/services/"+service+":disable", body)
}

func (c *Client) post(ctx context.Context, base, path, body string) error {
	u := strings.TrimRight(base, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	if c.QuotaProj != "" {
		req.Header.Set("x-goog-user-project", c.QuotaProj)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return &APIError{resp.StatusCode, errMsg(b), u}
	}
	return nil
}
