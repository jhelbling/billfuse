package gcp

import (
	"context"
	"fmt"
	"github.com/jhelbling/billfuse/internal/sev"
	"sort"
	"strings"
	"sync"
	"time"
)

type Severity = sev.Severity

const (
	Info     = sev.Info
	Low      = sev.Low
	Medium   = sev.Medium
	High     = sev.High
	Critical = sev.Critical
)

func ParseSeverity(s string) (Severity, bool) { return sev.Parse(s) }

// Services that can burn money fast when abused.
var AIServices = map[string]string{
	"generativelanguage.googleapis.com": "Gemini API",
	"aiplatform.googleapis.com":         "Vertex AI",
}

// KeyBillableServices are paid APIs that accept a bare API key, so an
// unrestricted key on a project with one of these enabled can run up a bill.
var KeyBillableServices = map[string]string{
	"translate.googleapis.com":                 "Cloud Translation",
	"vision.googleapis.com":                    "Cloud Vision",
	"speech.googleapis.com":                    "Speech-to-Text",
	"texttospeech.googleapis.com":              "Text-to-Speech",
	"language.googleapis.com":                  "Natural Language",
	"videointelligence.googleapis.com":         "Video Intelligence",
	"customsearch.googleapis.com":              "Custom Search",
	"maps-backend.googleapis.com":              "Maps JavaScript",
	"places-backend.googleapis.com":            "Places",
	"places.googleapis.com":                    "Places (New)",
	"geocoding-backend.googleapis.com":         "Geocoding",
	"directions-backend.googleapis.com":        "Directions",
	"distance-matrix-backend.googleapis.com":   "Distance Matrix",
	"routes.googleapis.com":                    "Routes",
	"static-maps-backend.googleapis.com":       "Maps Static",
	"street-view-image-backend.googleapis.com": "Street View Static",
	"elevation-backend.googleapis.com":         "Elevation",
	"timezone-backend.googleapis.com":          "Time Zone",
	"geolocation.googleapis.com":               "Geolocation",
	"roads.googleapis.com":                     "Roads",
	"aerialview.googleapis.com":                "Aerial View",
	"solar.googleapis.com":                     "Solar",
	"airquality.googleapis.com":                "Air Quality",
	"pollen.googleapis.com":                    "Pollen",
}

func svcName(s string) string {
	if n, ok := AIServices[s]; ok {
		return n
	}
	if n, ok := KeyBillableServices[s]; ok {
		return n
	}
	return strings.TrimSuffix(s, ".googleapis.com")
}

type KeyReport struct {
	Project      string    `json:"project"`
	ID           string    `json:"id"`
	UID          string    `json:"uid"`
	DisplayName  string    `json:"display_name"`
	CreateTime   time.Time `json:"create_time,omitempty"`
	Restricted   bool      `json:"api_restricted"`
	AppRestrict  bool      `json:"app_restricted"`
	Targets      []string  `json:"api_targets,omitempty"`
	UsageKnown   bool      `json:"usage_known"`
	Requests     int64     `json:"requests_window"`
	LastUsed     time.Time `json:"last_used,omitempty"`
	UsedServices []string  `json:"used_services,omitempty"`
	Risky        bool      `json:"risky"`
}

type Finding struct {
	Severity       Severity `json:"severity"`
	Code           string   `json:"code"`
	BillingAccount string   `json:"billing_account"`
	Project        string   `json:"project"`
	Resource       string   `json:"resource,omitempty"`
	Message        string   `json:"message"`
	Fix            string   `json:"fix,omitempty"`
}

type ProjectReport struct {
	ProjectID      string    `json:"project_id"`
	BillingAccount string    `json:"billing_account"`
	BillingEnabled bool      `json:"billing_enabled"`
	Visible        bool      `json:"visible"`
	Parent         string    `json:"parent,omitempty"`
	CreateTime     time.Time `json:"create_time,omitempty"`
	AIServices     []string  `json:"ai_services_enabled"`
	KeyBillable    []string  `json:"key_billable_services_enabled"`
	KeysTotal      int       `json:"api_keys_total"`
	KeysRisky      int       `json:"api_keys_risky"`
	Warnings       []string  `json:"warnings,omitempty"`
}

type Report struct {
	GeneratedAt     time.Time        `json:"generated_at"`
	BillingAccounts []BillingAccount `json:"billing_accounts"`
	Projects        []*ProjectReport `json:"projects"`
	Keys            []*KeyReport     `json:"keys"`
	Findings        []Finding        `json:"findings"`
	UsageDays       int              `json:"usage_window_days"`
	Warnings        []string         `json:"warnings,omitempty"`
}

type Options struct {
	BillingAccounts []string // empty = all visible
	Projects        []string // extra projects to audit (by ID) even if billing listing is denied
	RecentDays      int      // projects created within N days are flagged
	OldKeyDays      int
	UsageDays       int  // look-back for per-key usage (Cloud Monitoring keeps ~6 weeks)
	NoUsage         bool // skip the Monitoring query
	Concurrency     int
	Now             func() time.Time
}

func (o *Options) defaults() {
	if o.RecentDays == 0 {
		o.RecentDays = 30
	}
	if o.OldKeyDays == 0 {
		o.OldKeyDays = 365
	}
	if o.UsageDays <= 0 {
		o.UsageDays = 30
	}
	if o.UsageDays > 42 {
		o.UsageDays = 42
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

func Audit(ctx context.Context, c *Client, o Options) (*Report, error) {
	o.defaults()
	now := o.Now()
	rep := &Report{GeneratedAt: now.UTC(), UsageDays: o.UsageDays}
	if o.NoUsage {
		rep.UsageDays = 0
	}

	// 1. Billing accounts.
	var accounts []BillingAccount
	if len(o.BillingAccounts) > 0 {
		for _, id := range o.BillingAccounts {
			id = strings.TrimPrefix(id, "billingAccounts/")
			ba, err := c.GetBillingAccount(ctx, id)
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("billing account %s: %v", id, err))
				ba = BillingAccount{Name: "billingAccounts/" + id}
			}
			accounts = append(accounts, ba)
		}
	} else {
		var err error
		accounts, err = c.ListBillingAccounts(ctx)
		if err != nil {
			if len(o.Projects) == 0 {
				return nil, fmt.Errorf("listing billing accounts: %w (need roles/billing.viewer, or pass --project)", err)
			}
			rep.Warnings = append(rep.Warnings, "cannot list billing accounts: "+err.Error())
		}
	}
	rep.BillingAccounts = accounts

	// 2. Projects attached to each account.
	type target struct {
		ba   string
		info ProjectBillingInfo
	}
	var targets []target
	seen := map[string]bool{}
	for _, ba := range accounts {
		id := strings.TrimPrefix(ba.Name, "billingAccounts/")
		if !ba.Open && ba.DisplayName != "" {
			rep.Findings = append(rep.Findings, Finding{Severity: Info, Code: "BA_CLOSED", BillingAccount: id,
				Message: "billing account is closed"})
		}
		ps, err := c.ListBillingProjects(ctx, id)
		if err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("billing account %s: cannot list projects: %v", id, err))
			continue
		}
		active := 0
		for _, p := range ps {
			if p.BillingEnabled {
				active++
			}
			if !seen[p.ProjectID] {
				seen[p.ProjectID] = true
				targets = append(targets, target{id, p})
			}
		}
		if active == 0 && ba.Open {
			rep.Findings = append(rep.Findings, Finding{Severity: Low, Code: "BA_DORMANT_OPEN", BillingAccount: id,
				Message: "open billing account with no billed projects",
				Fix:     "close it, or restrict roles/billing.user on it"})
		}
	}
	for _, p := range o.Projects {
		if !seen[p] {
			seen[p] = true
			targets = append(targets, target{"", ProjectBillingInfo{ProjectID: p, BillingEnabled: true}})
		}
	}

	// 3. Per-project checks, bounded concurrency.
	var mu sync.Mutex
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			pr, keys, fs := auditProject(ctx, c, t.ba, t.info, o, now)
			mu.Lock()
			rep.Projects = append(rep.Projects, pr)
			rep.Keys = append(rep.Keys, keys...)
			rep.Findings = append(rep.Findings, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 4. Cross-project: projects whose org differs from the account's dominant org.
	rep.Findings = append(rep.Findings, orgOutliers(rep.Projects)...)

	sort.Slice(rep.Keys, func(i, j int) bool {
		if rep.Keys[i].Project != rep.Keys[j].Project {
			return rep.Keys[i].Project < rep.Keys[j].Project
		}
		return rep.Keys[i].DisplayName < rep.Keys[j].DisplayName
	})
	sort.Slice(rep.Projects, func(i, j int) bool { return rep.Projects[i].ProjectID < rep.Projects[j].ProjectID })
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Resource < b.Resource
	})
	return rep, nil
}

func auditProject(ctx context.Context, c *Client, ba string, info ProjectBillingInfo, o Options, now time.Time) (*ProjectReport, []*KeyReport, []Finding) {
	pid := info.ProjectID
	pr := &ProjectReport{ProjectID: pid, BillingAccount: ba, BillingEnabled: info.BillingEnabled, AIServices: []string{}, KeyBillable: []string{}}
	var fs []Finding
	add := func(sev Severity, code, res, msg, fix string) {
		fs = append(fs, Finding{sev, code, ba, pid, res, msg, fix})
	}

	proj, err := c.GetProject(ctx, pid)
	switch {
	case err == nil:
		pr.Visible = true
		pr.Parent = proj.Parent
		pr.CreateTime = proj.CreateTime
		if info.BillingEnabled && !proj.CreateTime.IsZero() && now.Sub(proj.CreateTime) < time.Duration(o.RecentDays)*24*time.Hour {
			add(Medium, "PROJECT_RECENT", "", fmt.Sprintf("project created %s (%d days ago) and is billed to this account - confirm you created it",
				proj.CreateTime.Format("2006-01-02"), int(now.Sub(proj.CreateTime).Hours()/24)), "")
		}
		if proj.Parent == "" {
			add(Low, "PROJECT_NO_ORG", "", "project has no organization/folder parent - no org policies or central IAM apply", "")
		}
	case IsForbiddenOrNotFound(err):
		if info.BillingEnabled {
			add(Critical, "PROJECT_INVISIBLE", "",
				"project is billed to this account but you cannot see it. It may belong to someone else",
				"if you don't own it: gcloud billing projects unlink "+pid+" ; then lock down roles/billing.user on the account")
		} else {
			add(Info, "PROJECT_INVISIBLE_UNBILLED", "", "project linked with billing disabled and not visible to you", "")
		}
		pr.Warnings = append(pr.Warnings, "project not readable; service and key checks skipped")
		return pr, nil, fs
	default:
		pr.Warnings = append(pr.Warnings, "get project: "+err.Error())
	}

	svcs, err := c.EnabledServices(ctx, pid)
	if err != nil {
		pr.Warnings = append(pr.Warnings, "list services: "+err.Error())
		svcs = nil
	}
	for s := range AIServices {
		if svcs[s] {
			pr.AIServices = append(pr.AIServices, s)
		}
	}
	sort.Strings(pr.AIServices)
	for s := range KeyBillableServices {
		if svcs[s] {
			pr.KeyBillable = append(pr.KeyBillable, s)
		}
	}
	sort.Strings(pr.KeyBillable)
	if svcs["generativelanguage.googleapis.com"] && info.BillingEnabled {
		add(Info, "GEMINI_ENABLED", "", "Gemini API (generativelanguage) enabled on a billed project", "")
	}

	keys, err := c.ListAPIKeys(ctx, pid)
	if err != nil {
		if !(IsForbiddenOrNotFound(err) && svcs != nil && !svcs["apikeys.googleapis.com"]) {
			pr.Warnings = append(pr.Warnings, "list api keys: "+err.Error())
		}
		return pr, nil, fs
	}
	pr.KeysTotal = len(keys)

	var usage map[string]*KeyUsage
	if len(keys) > 0 && !o.NoUsage {
		usage, err = c.KeyUsageByUID(ctx, pid, now.Add(-time.Duration(o.UsageDays)*24*time.Hour), now)
		if err != nil {
			pr.Warnings = append(pr.Warnings, "per-key usage (needs roles/monitoring.viewer): "+err.Error())
			usage = nil
		}
	}

	var krs []*KeyReport
	for _, k := range keys {
		kr := newKeyReport(pid, k)
		if usage != nil {
			kr.UsageKnown = true
			if u := usage[k.UID]; u != nil {
				kr.Requests, kr.LastUsed = u.Requests, u.LastUsed
				for s := range u.Services {
					kr.UsedServices = append(kr.UsedServices, s)
				}
				sort.Strings(kr.UsedServices)
			}
		}
		kf := classifyKey(k, kr, svcs, info.BillingEnabled, o, now)
		kr.Risky = len(kf) > 0
		if kr.Risky {
			pr.KeysRisky++
		}
		krs = append(krs, kr)
		for _, f := range kf {
			f.BillingAccount, f.Project = ba, pid
			fs = append(fs, f)
		}
	}
	return pr, krs, fs
}

func newKeyReport(pid string, k APIKey) *KeyReport {
	kr := &KeyReport{Project: pid, ID: k.Name[strings.LastIndex(k.Name, "/")+1:], UID: k.UID, DisplayName: k.DisplayName, CreateTime: k.CreateTime}
	if r := k.Restrictions; r != nil {
		// An empty restriction object (e.g. "androidKeyRestrictions": {}) restricts nothing.
		kr.AppRestrict = (r.BrowserKeyRestrictions != nil && len(r.BrowserKeyRestrictions.AllowedReferrers) > 0) ||
			(r.ServerKeyRestrictions != nil && len(r.ServerKeyRestrictions.AllowedIPs) > 0) ||
			(r.AndroidKeyRestrictions != nil && len(r.AndroidKeyRestrictions.AllowedApplications) > 0) ||
			(r.IOSKeyRestrictions != nil && len(r.IOSKeyRestrictions.AllowedBundleIDs) > 0)
		for _, t := range r.APITargets {
			kr.Targets = append(kr.Targets, t.Service)
		}
	}
	kr.Restricted = len(kr.Targets) > 0
	return kr
}

func keyLabel(k APIKey) string {
	id := k.Name[strings.LastIndex(k.Name, "/")+1:]
	if k.DisplayName != "" {
		return fmt.Sprintf("%s (%s)", k.DisplayName, id)
	}
	return id
}

func names(ss []string) string {
	var out []string
	for _, s := range ss {
		out = append(out, svcName(s))
	}
	return strings.Join(out, ", ")
}

func classifyKey(k APIKey, kr *KeyReport, svcs map[string]bool, billed bool, o Options, now time.Time) []Finding {
	var fs []Finding
	res := keyLabel(k)
	fix := "restrict the key to only the APIs it needs (+ an application restriction); rotate if it ever shipped in a client"

	// Usage and age context, appended to every finding for this key.
	var ctxt []string
	old := !k.CreateTime.IsZero() && now.Sub(k.CreateTime) > time.Duration(o.OldKeyDays)*24*time.Hour
	if !k.CreateTime.IsZero() {
		s := "created " + k.CreateTime.Format("2006-01-02")
		if old {
			s += ""
		}
		ctxt = append(ctxt, s)
	}
	unused := false
	if kr.UsageKnown {
		if kr.Requests == 0 {
			unused = true
			ctxt = append(ctxt, fmt.Sprintf("no requests in the last %d days", o.UsageDays))
		} else {
			ctxt = append(ctxt, fmt.Sprintf("%d requests in %dd, last %s, via %s", kr.Requests, o.UsageDays, kr.LastUsed.Format("2006-01-02"), names(kr.UsedServices)))
		}
	}
	if unused {
		fix = "unused -> delete it: gcloud services api-keys delete " + kr.ID + " --project " + kr.Project + "  (if Google refuses due to recent usage: curl -X DELETE .../keys/" + kr.ID + "?checkExistingUsage=SKIP, or delete in Console)"
	} else if kr.UsageKnown && len(kr.UsedServices) > 0 && !kr.Restricted {
		fix = "restrict to what it actually uses: gcloud services api-keys update " + kr.ID + " --project " + kr.Project
		for _, s := range kr.UsedServices {
			fix += " --api-target=service=" + s
		}
	}
	add := func(sev Severity, code, msg string) {
		if !billed && sev > Low {
			sev = Low
		}
		if len(ctxt) > 0 {
			msg += " · " + strings.Join(ctxt, " · ")
		}
		fs = append(fs, Finding{Severity: sev, Code: code, Resource: res, Message: msg, Fix: fix})
	}

	var aiOn, billOn []string
	for s := range svcs {
		if _, ok := AIServices[s]; ok {
			aiOn = append(aiOn, s)
		} else if _, ok := KeyBillableServices[s]; ok {
			billOn = append(billOn, s)
		}
	}
	sort.Strings(aiOn)
	sort.Strings(billOn)

	if !kr.Restricted {
		switch {
		case len(aiOn) > 0:
			add(Critical, "KEY_UNRESTRICTED_AI", "no API restrictions and "+names(aiOn)+" is enabled - anyone holding this key can bill you for AI calls")
		case len(billOn) > 0:
			add(High, "KEY_UNRESTRICTED_BILLABLE", "no API restrictions and paid key-callable API(s) enabled: "+names(billOn)+" - a leaked key bills you directly")
		default:
			add(Medium, "KEY_UNRESTRICTED", "no API restrictions - no paid key-callable API is enabled today, but the key silently gains access to any enabled later (incl. Gemini)")
		}
		return fs
	}
	for _, t := range kr.Targets {
		if name, ok := AIServices[t]; ok {
			if kr.AppRestrict {
				add(Medium, "KEY_AI_ACCESS", "can call "+name+" (has an application restriction, but referrer/app restrictions are spoofable)")
			} else {
				add(High, "KEY_AI_ACCESS", "can call "+name+" and has no application restriction")
			}
		} else if name, ok := KeyBillableServices[t]; ok && svcs[t] && !kr.AppRestrict {
			add(Medium, "KEY_BILLABLE_ACCESS", "can call paid "+name+" with no application restriction")
		}
	}
	return fs
}

// orgOutliers flags visible projects on a billing account that sit in a different
// organization than most of that account's projects.
func orgOutliers(ps []*ProjectReport) []Finding {
	orgOf := func(parent string) string {
		if strings.HasPrefix(parent, "organizations/") {
			return parent
		}
		return "" // folders need an extra lookup; skip to stay cheap
	}
	byBA := map[string][]*ProjectReport{}
	for _, p := range ps {
		if p.Visible && p.BillingAccount != "" {
			byBA[p.BillingAccount] = append(byBA[p.BillingAccount], p)
		}
	}
	var fs []Finding
	for ba, list := range byBA {
		count := map[string]int{}
		for _, p := range list {
			if o := orgOf(p.Parent); o != "" {
				count[o]++
			}
		}
		if len(count) < 2 {
			continue
		}
		dominant, best := "", 0
		for o, n := range count {
			if n > best || (n == best && o < dominant) {
				dominant, best = o, n
			}
		}
		for _, p := range list {
			if o := orgOf(p.Parent); o != "" && o != dominant && p.BillingEnabled {
				fs = append(fs, Finding{Severity: High, Code: "PROJECT_FOREIGN_ORG", BillingAccount: ba, Project: p.ProjectID,
					Message: fmt.Sprintf("project lives in %s, while most projects on this account are in %s", o, dominant),
					Fix:     "confirm ownership; unlink if unknown"})
			}
		}
	}
	return fs
}
