package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Endpoint returns the base URL for a service in a region. Tests swap it.
type Endpoint func(service, region string) string

func DefaultEndpoint(service, region string) string {
	switch service {
	case "iam":
		return "https://iam.amazonaws.com"
	case "sts":
		return "https://sts.amazonaws.com"
	case "organizations":
		return "https://organizations.us-east-1.amazonaws.com"
	}
	return "https://" + service + "." + region + ".amazonaws.com"
}

type Client struct {
	HTTP     *http.Client
	Creds    Credentials
	Endpoint Endpoint
	Now      func() time.Time
}

type APIError struct {
	Status  int
	Code    string
	Message string
	Op      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: HTTP %d %s: %s", e.Op, e.Status, e.Code, e.Message)
}

// IsRegionDisabled reports errors that just mean "this opt-in region is not enabled for the account".
func IsRegionDisabled(err error) bool {
	ae, ok := err.(*APIError)
	if !ok {
		return false
	}
	return ae.Code == "InvalidClientTokenId" || ae.Code == "UnrecognizedClientException" ||
		strings.Contains(ae.Message, "security token included in the request is invalid")
}

func IsAccessDenied(err error) bool {
	ae, ok := err.(*APIError)
	return ok && (ae.Status == 403 || strings.Contains(ae.Code, "AccessDenied"))
}

var readOnlyPrefixes = []string{"List", "Get", "Describe"}

// query calls an AWS Query-protocol API (IAM, STS, CloudWatch). Only
// List*/Get*/Describe* actions are permitted - read-only by construction.
func (c *Client) query(ctx context.Context, service, region, version, action string, params url.Values, out any) error {
	ok := false
	for _, p := range readOnlyPrefixes {
		if strings.HasPrefix(action, p) {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("refusing non-read-only action %s", action)
	}
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("Action", action)
	form.Set("Version", version)
	body := []byte(form.Encode())
	sigRegion := region
	if service == "iam" || service == "sts" {
		sigRegion = "us-east-1"
	}
	base := strings.TrimRight(c.Endpoint(service, region), "/") + "/"
	return c.do(ctx, "POST", base, body, "application/x-www-form-urlencoded; charset=utf-8", sigRegion, service, action, func(b []byte) error {
		return xml.Unmarshal(b, out)
	})
}

// restGet calls a REST/JSON API with GET (Bedrock control plane).
func (c *Client) restGet(ctx context.Context, service, region, path string, out any) error {
	u := strings.TrimRight(c.Endpoint(service, region), "/") + path
	return c.do(ctx, "GET", u, nil, "", region, service, "GET "+path, func(b []byte) error {
		if len(bytes.TrimSpace(b)) == 0 {
			return nil
		}
		return json.Unmarshal(b, out)
	})
}

func (c *Client) do(ctx context.Context, method, u string, body []byte, ctype, region, service, op string, decode func([]byte) error) error {
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		req.Header.Set("User-Agent", "billfuse-audit/0.3")
		now := time.Now
		if c.Now != nil {
			now = c.Now
		}
		Sign(req, body, c.Creds, region, service, now())
		resp, err := c.HTTP.Do(req)
		if err != nil {
			last = err
			time.Sleep(time.Duration(attempt+1) * 400 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return decode(b)
		}
		ae := parseErr(resp.StatusCode, b, op)
		if resp.StatusCode == 429 || resp.StatusCode >= 500 || ae.Code == "Throttling" || ae.Code == "ThrottlingException" {
			last = ae
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		return ae
	}
	return last
}

func parseErr(status int, b []byte, op string) *APIError {
	var x struct {
		Error struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Error"`
	}
	if xml.Unmarshal(b, &x) == nil && x.Error.Code != "" {
		return &APIError{status, x.Error.Code, x.Error.Message, op}
	}
	var j struct {
		Message string `json:"message"`
		Type    string `json:"__type"`
	}
	if json.Unmarshal(b, &j) == nil && (j.Message != "" || j.Type != "") {
		return &APIError{status, j.Type, j.Message, op}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return &APIError{status, "", s, op}
}

// ---------- STS ----------

type Identity struct {
	Account string `xml:"GetCallerIdentityResult>Account"`
	Arn     string `xml:"GetCallerIdentityResult>Arn"`
}

func (c *Client) CallerIdentity(ctx context.Context) (Identity, error) {
	var id Identity
	err := c.query(ctx, "sts", "us-east-1", "2011-06-15", "GetCallerIdentity", nil, &id)
	return id, err
}

// ---------- IAM ----------

const iamVersion = "2010-05-08"

type AttachedPolicy struct {
	Name string `xml:"PolicyName"`
	Arn  string `xml:"PolicyArn"`
}

type InlinePolicy struct {
	Name     string `xml:"PolicyName"`
	Document string `xml:"PolicyDocument"` // URL-encoded JSON
}

type Boundary struct {
	Arn string `xml:"PermissionsBoundaryArn"`
}

type UserDetail struct {
	UserName   string           `xml:"UserName"`
	Arn        string           `xml:"Arn"`
	CreateDate time.Time        `xml:"CreateDate"`
	Groups     []string         `xml:"GroupList>member"`
	Attached   []AttachedPolicy `xml:"AttachedManagedPolicies>member"`
	Inline     []InlinePolicy   `xml:"UserPolicyList>member"`
	Boundary   *Boundary        `xml:"PermissionsBoundary"`
}

type GroupDetail struct {
	GroupName string           `xml:"GroupName"`
	Attached  []AttachedPolicy `xml:"AttachedManagedPolicies>member"`
	Inline    []InlinePolicy   `xml:"GroupPolicyList>member"`
}

type RoleDetail struct {
	RoleName   string           `xml:"RoleName"`
	Arn        string           `xml:"Arn"`
	Path       string           `xml:"Path"`
	Trust      string           `xml:"AssumeRolePolicyDocument"`
	Attached   []AttachedPolicy `xml:"AttachedManagedPolicies>member"`
	Inline     []InlinePolicy   `xml:"RolePolicyList>member"`
	Boundary   *Boundary        `xml:"PermissionsBoundary"`
	LastUsed   time.Time        `xml:"RoleLastUsed>LastUsedDate"`
	CreateDate time.Time        `xml:"CreateDate"`
}

type ManagedPolicy struct {
	Name     string `xml:"PolicyName"`
	Arn      string `xml:"Arn"`
	Versions []struct {
		Document  string `xml:"Document"`
		IsDefault bool   `xml:"IsDefaultVersion"`
	} `xml:"PolicyVersionList>member"`
}

func (m ManagedPolicy) DefaultDoc() string {
	for _, v := range m.Versions {
		if v.IsDefault {
			return v.Document
		}
	}
	if len(m.Versions) > 0 {
		return m.Versions[0].Document
	}
	return ""
}

type AuthDetails struct {
	Users    []UserDetail
	Groups   []GroupDetail
	Roles    []RoleDetail
	Policies map[string]ManagedPolicy // by ARN
}

func (c *Client) AuthorizationDetails(ctx context.Context) (*AuthDetails, error) {
	out := &AuthDetails{Policies: map[string]ManagedPolicy{}}
	marker := ""
	for {
		p := url.Values{
			"Filter.member.1": {"User"}, "Filter.member.2": {"Role"}, "Filter.member.3": {"Group"},
			"Filter.member.4": {"LocalManagedPolicy"}, "Filter.member.5": {"AWSManagedPolicy"},
			"MaxItems": {"1000"},
		}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			Users       []UserDetail    `xml:"GetAccountAuthorizationDetailsResult>UserDetailList>member"`
			Groups      []GroupDetail   `xml:"GetAccountAuthorizationDetailsResult>GroupDetailList>member"`
			Roles       []RoleDetail    `xml:"GetAccountAuthorizationDetailsResult>RoleDetailList>member"`
			Policies    []ManagedPolicy `xml:"GetAccountAuthorizationDetailsResult>Policies>member"`
			IsTruncated bool            `xml:"GetAccountAuthorizationDetailsResult>IsTruncated"`
			Marker      string          `xml:"GetAccountAuthorizationDetailsResult>Marker"`
		}
		if err := c.query(ctx, "iam", "us-east-1", iamVersion, "GetAccountAuthorizationDetails", p, &r); err != nil {
			return nil, err
		}
		out.Users = append(out.Users, r.Users...)
		out.Groups = append(out.Groups, r.Groups...)
		out.Roles = append(out.Roles, r.Roles...)
		for _, pol := range r.Policies {
			out.Policies[pol.Arn] = pol
		}
		if !r.IsTruncated || r.Marker == "" {
			return out, nil
		}
		marker = r.Marker
	}
}

type AccessKey struct {
	UserName   string    `xml:"UserName"`
	ID         string    `xml:"AccessKeyId"`
	Status     string    `xml:"Status"`
	CreateDate time.Time `xml:"CreateDate"`
	LastUsed   time.Time `xml:"-"`
	LastSvc    string    `xml:"-"`
	LastRegion string    `xml:"-"`
}

func (c *Client) AccessKeys(ctx context.Context, user string) ([]AccessKey, error) {
	var all []AccessKey
	marker := ""
	for {
		p := url.Values{"UserName": {user}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			Keys        []AccessKey `xml:"ListAccessKeysResult>AccessKeyMetadata>member"`
			IsTruncated bool        `xml:"ListAccessKeysResult>IsTruncated"`
			Marker      string      `xml:"ListAccessKeysResult>Marker"`
		}
		if err := c.query(ctx, "iam", "us-east-1", iamVersion, "ListAccessKeys", p, &r); err != nil {
			return nil, err
		}
		all = append(all, r.Keys...)
		if !r.IsTruncated || r.Marker == "" {
			break
		}
		marker = r.Marker
	}
	for i := range all {
		var r struct {
			Date    string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>LastUsedDate"`
			Service string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>ServiceName"`
			Region  string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>Region"`
		}
		if err := c.query(ctx, "iam", "us-east-1", iamVersion, "GetAccessKeyLastUsed", url.Values{"AccessKeyId": {all[i].ID}}, &r); err != nil {
			return all, err
		}
		if t, err := time.Parse(time.RFC3339, r.Date); err == nil {
			all[i].LastUsed = t
		}
		if r.Service != "N/A" {
			all[i].LastSvc = r.Service
		}
		if r.Region != "N/A" {
			all[i].LastRegion = r.Region
		}
	}
	return all, nil
}

func (c *Client) AccountSummary(ctx context.Context) (map[string]int, error) {
	var r struct {
		Entries []struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		} `xml:"GetAccountSummaryResult>SummaryMap>entry"`
	}
	if err := c.query(ctx, "iam", "us-east-1", iamVersion, "GetAccountSummary", nil, &r); err != nil {
		return nil, err
	}
	m := map[string]int{}
	for _, e := range r.Entries {
		n, _ := strconv.Atoi(e.Value)
		m[e.Key] = n
	}
	return m, nil
}

// ---------- CloudWatch (AWS/Bedrock) ----------

const cwVersion = "2010-08-01"

// BedrockModelsWithTraffic lists ModelIds that have an Invocations metric in
// the region (CloudWatch ListMetrics only returns metrics with data in ~2 weeks).
func (c *Client) BedrockModelsWithTraffic(ctx context.Context, region string) ([]string, error) {
	var models []string
	seen := map[string]bool{}
	tok := ""
	for {
		p := url.Values{"Namespace": {"AWS/Bedrock"}, "MetricName": {"Invocations"}}
		if tok != "" {
			p.Set("NextToken", tok)
		}
		var r struct {
			Metrics []struct {
				Dims []struct {
					Name  string `xml:"Name"`
					Value string `xml:"Value"`
				} `xml:"Dimensions>member"`
			} `xml:"ListMetricsResult>Metrics>member"`
			Next string `xml:"ListMetricsResult>NextToken"`
		}
		if err := c.query(ctx, "monitoring", region, cwVersion, "ListMetrics", p, &r); err != nil {
			return nil, err
		}
		for _, m := range r.Metrics {
			for _, d := range m.Dims {
				if d.Name == "ModelId" && !seen[d.Value] {
					seen[d.Value] = true
					models = append(models, d.Value)
				}
			}
		}
		if r.Next == "" {
			return models, nil
		}
		tok = r.Next
	}
}

// BedrockSum returns the daily sums of a metric for one model over [start,end].
func (c *Client) BedrockSum(ctx context.Context, region, metric, model string, start, end time.Time) (total float64, last time.Time, err error) {
	p := url.Values{
		"Namespace": {"AWS/Bedrock"}, "MetricName": {metric},
		"Dimensions.member.1.Name": {"ModelId"}, "Dimensions.member.1.Value": {model},
		"StartTime": {start.UTC().Format(time.RFC3339)}, "EndTime": {end.UTC().Format(time.RFC3339)},
		"Period": {"86400"}, "Statistics.member.1": {"Sum"},
	}
	var r struct {
		Points []struct {
			Timestamp time.Time `xml:"Timestamp"`
			Sum       float64   `xml:"Sum"`
		} `xml:"GetMetricStatisticsResult>Datapoints>member"`
	}
	if err = c.query(ctx, "monitoring", region, cwVersion, "GetMetricStatistics", p, &r); err != nil {
		return
	}
	for _, pt := range r.Points {
		total += pt.Sum
		if pt.Sum > 0 && pt.Timestamp.After(last) {
			last = pt.Timestamp
		}
	}
	return
}

// ---------- Bedrock control plane ----------

// InvocationLoggingEnabled reports whether model invocation logging is configured in the region.
func (c *Client) InvocationLoggingEnabled(ctx context.Context, region string) (bool, error) {
	var r struct {
		LoggingConfig map[string]any `json:"loggingConfig"`
	}
	if err := c.restGet(ctx, "bedrock", region, "/logging/modelinvocations", &r); err != nil {
		return false, err
	}
	if r.LoggingConfig == nil {
		return false, nil
	}
	_, cw := r.LoggingConfig["cloudWatchConfig"]
	_, s3 := r.LoggingConfig["s3Config"]
	return cw || s3, nil
}

// ---------- Organizations ----------

// ManagementAccount returns the org's management account ID ("" if not in an org).
func (c *Client) ManagementAccount(ctx context.Context) (string, error) {
	body := []byte("{}")
	u := strings.TrimRight(c.Endpoint("organizations", "us-east-1"), "/") + "/"
	var r struct {
		Organization struct {
			MasterAccountID string `json:"MasterAccountId"`
		} `json:"Organization"`
	}
	err := c.doJSON(ctx, u, body, "AWSOrganizationsV20161128.DescribeOrganization", "us-east-1", "organizations", &r)
	if ae, ok := err.(*APIError); ok && strings.Contains(ae.Code, "AWSOrganizationsNotInUse") {
		return "", nil
	}
	return r.Organization.MasterAccountID, err
}

func (c *Client) doJSON(ctx context.Context, u string, body []byte, target, region, service string, out any) error {
	op := target[strings.LastIndex(target, ".")+1:]
	if !(strings.HasPrefix(op, "Describe") || strings.HasPrefix(op, "List") || strings.HasPrefix(op, "Get")) {
		return fmt.Errorf("refusing non-read-only action %s", op)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	Sign(req, body, c.Creds, region, service, now())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return parseErr(resp.StatusCode, b, op)
	}
	return json.Unmarshal(b, out)
}

// BedrockWindowSum sums a metric for one model over [start,end] as a single datapoint.
func (c *Client) BedrockWindowSum(ctx context.Context, region, metric, model string, start, end time.Time) (float64, error) {
	secs := int(end.Sub(start).Seconds())
	secs = (secs + 59) / 60 * 60
	if secs < 60 {
		secs = 60
	}
	p := url.Values{
		"Namespace": {"AWS/Bedrock"}, "MetricName": {metric},
		"Dimensions.member.1.Name": {"ModelId"}, "Dimensions.member.1.Value": {model},
		"StartTime": {start.UTC().Format(time.RFC3339)}, "EndTime": {end.UTC().Format(time.RFC3339)},
		"Period": {strconv.Itoa(secs)}, "Statistics.member.1": {"Sum"},
	}
	var r struct {
		Points []struct {
			Sum float64 `xml:"Sum"`
		} `xml:"GetMetricStatisticsResult>Datapoints>member"`
	}
	if err := c.query(ctx, "monitoring", region, cwVersion, "GetMetricStatistics", p, &r); err != nil {
		return 0, err
	}
	var total float64
	for _, pt := range r.Points {
		total += pt.Sum
	}
	return total, nil
}

// ---------- Kill-switch writes (used only by `watch --act`) ----------

// DenyBedrockPolicyName is the inline policy billfuse attaches when it trips.
const DenyBedrockPolicyName = "billfuse-deny-bedrock"

const denyBedrockDoc = `{"Version":"2012-10-17","Statement":[{"Sid":"BillfuseKillSwitch","Effect":"Deny","Action":"bedrock:*","Resource":"*"}]}`

// PutDenyBedrock attaches an inline Deny bedrock:* policy to a role or user.
// kind is "role" or "user". Remove it with: aws iam delete-role-policy --role-name X --policy-name billfuse-deny-bedrock
func (c *Client) PutDenyBedrock(ctx context.Context, kind, name string) error {
	action, key := "PutRolePolicy", "RoleName"
	if kind == "user" {
		action, key = "PutUserPolicy", "UserName"
	}
	form := url.Values{
		"Action": {action}, "Version": {iamVersion}, key: {name},
		"PolicyName": {DenyBedrockPolicyName}, "PolicyDocument": {denyBedrockDoc},
	}
	body := []byte(form.Encode())
	base := strings.TrimRight(c.Endpoint("iam", "us-east-1"), "/") + "/"
	return c.do(ctx, "POST", base, body, "application/x-www-form-urlencoded; charset=utf-8", "us-east-1", "iam", action, func([]byte) error { return nil })
}
