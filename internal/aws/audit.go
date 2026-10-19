package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jhelbling/billfuse/internal/sev"
)

// BedrockRegions where Bedrock runtime is offered (commercial partition).
var BedrockRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "sa-east-1",
	"eu-central-1", "eu-central-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-south-2",
	"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7",
	"me-central-1", "me-south-1", "il-central-1", "af-south-1", "mx-central-1",
}

type Finding struct {
	Severity sev.Severity `json:"severity"`
	Code     string       `json:"code"`
	Account  string       `json:"account"`
	Resource string       `json:"resource,omitempty"`
	Message  string       `json:"message"`
	Fix      string       `json:"fix,omitempty"`
}

type KeyInfo struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	Created    time.Time `json:"created"`
	LastUsed   time.Time `json:"last_used,omitempty"`
	LastSvc    string    `json:"last_service,omitempty"`
	LastRegion string    `json:"last_region,omitempty"`
}

type Principal struct {
	Type        string    `json:"type"` // user | role
	Name        string    `json:"name"`
	Arn         string    `json:"arn"`
	Via         []string  `json:"via"`
	Conditional bool      `json:"conditional"`
	Keys        []KeyInfo `json:"access_keys,omitempty"`
	RoleLastUse time.Time `json:"role_last_used,omitempty"`
	Trust       string    `json:"trust_risk,omitempty"`
	TrustWho    []string  `json:"trust_principals,omitempty"`
}

type ModelUsage struct {
	Model        string    `json:"model"`
	Invocations  float64   `json:"invocations"`
	InputTokens  float64   `json:"input_tokens"`
	OutputTokens float64   `json:"output_tokens"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
}

type RegionUsage struct {
	Region  string       `json:"region"`
	Models  []ModelUsage `json:"models"`
	Logging *bool        `json:"invocation_logging,omitempty"`
}

type Report struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Account     string         `json:"account"`
	Caller      string         `json:"caller"`
	Principals  []*Principal   `json:"bedrock_principals"`
	Regions     []*RegionUsage `json:"bedrock_usage"`
	UsageDays   int            `json:"usage_window_days"`
	Findings    []Finding      `json:"findings"`
	Warnings    []string       `json:"warnings,omitempty"`
	Stats       map[string]int `json:"stats"`
	OrgMgmt     string         `json:"org_management_account,omitempty"`
}

type Options struct {
	Regions         []string // default: BedrockRegions
	ExpectedRegions []string // usage outside these -> HIGH
	DormantDays     int      // key unused this long = dormant (default 90)
	OldKeyDays      int      // key older than this = old (default 365)
	UsageDays       int      // CloudWatch look-back (default 30)
	NoUsage         bool
	Concurrency     int
	Now             func() time.Time
}

func (o *Options) defaults() {
	if len(o.Regions) == 0 {
		o.Regions = BedrockRegions
	}
	if o.DormantDays == 0 {
		o.DormantDays = 90
	}
	if o.OldKeyDays == 0 {
		o.OldKeyDays = 365
	}
	if o.UsageDays == 0 {
		o.UsageDays = 30
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
	rep := &Report{GeneratedAt: now.UTC(), UsageDays: o.UsageDays, Stats: map[string]int{}}
	if o.NoUsage {
		rep.UsageDays = 0
	}

	id, err := c.CallerIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	rep.Account, rep.Caller = id.Account, id.Arn
	acct := id.Account
	add := func(s sev.Severity, code, res, msg, fix string) {
		rep.Findings = append(rep.Findings, Finding{s, code, acct, res, msg, fix})
	}

	if strings.HasSuffix(id.Arn, ":root") {
		add(sev.High, "CALLER_IS_ROOT", "root", "you are running this with root credentials", "use an IAM role / IAM Identity Center user instead")
	}
	if sum, err := c.AccountSummary(ctx); err != nil {
		rep.Warnings = append(rep.Warnings, "iam:GetAccountSummary: "+err.Error())
	} else if sum["AccountAccessKeysPresent"] > 0 {
		add(sev.Critical, "ROOT_ACCESS_KEY", "root",
			"the root user has access keys - a leaked root key can enable any model in any region",
			"delete root access keys (IAM console -> Security credentials as root)")
	}

	if m, err := c.ManagementAccount(ctx); err == nil {
		rep.OrgMgmt = m
	}

	// ---- IAM: who can invoke Bedrock? ----
	ad, err := c.AuthorizationDetails(ctx)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "iam:GetAccountAuthorizationDetails (needs iam:GetAccountAuthorizationDetails, e.g. SecurityAudit): "+err.Error())
	} else {
		rep.Stats["users"], rep.Stats["roles"] = len(ad.Users), len(ad.Roles)
		auditIAM(ctx, c, ad, rep, o, now, add)
	}

	// ---- CloudWatch: where is Bedrock actually used? ----
	if !o.NoUsage {
		auditUsage(ctx, c, rep, o, now, add)
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Resource < b.Resource
	})
	return rep, nil
}

func managedDocs(ad *AuthDetails, att []AttachedPolicy) []NamedDoc {
	var out []NamedDoc
	for _, a := range att {
		if p, ok := ad.Policies[a.Arn]; ok {
			out = append(out, NamedDoc{a.Name, p.DefaultDoc()})
		}
	}
	return out
}

func inlineDocs(in []InlinePolicy) []NamedDoc {
	var out []NamedDoc
	for _, p := range in {
		out = append(out, NamedDoc{p.Name + " (inline)", p.Document})
	}
	return out
}

func boundaryBlocks(ad *AuthDetails, b *Boundary) bool {
	if b == nil || b.Arn == "" {
		return false
	}
	p, ok := ad.Policies[b.Arn]
	if !ok {
		return false // unknown boundary: be conservative, assume it allows
	}
	return !EvaluateInvoke([]NamedDoc{{"boundary", p.DefaultDoc()}}).Allowed
}

func auditIAM(ctx context.Context, c *Client, ad *AuthDetails, rep *Report, o Options, now time.Time,
	add func(sev.Severity, string, string, string, string)) {
	groups := map[string]GroupDetail{}
	for _, g := range ad.Groups {
		groups[g.GroupName] = g
	}
	days := func(t time.Time) int { return int(now.Sub(t).Hours() / 24) }

	// Users: identity policies (direct + groups); keys fetched for every user with active keys.
	type uk struct {
		u    UserDetail
		keys []AccessKey
		err  error
	}
	results := make([]uk, len(ad.Users))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, u := range ad.Users {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u UserDetail) {
			defer wg.Done()
			defer func() { <-sem }()
			k, err := c.AccessKeys(ctx, u.UserName)
			results[i] = uk{u, k, err}
		}(i, u)
	}
	wg.Wait()

	for _, r := range results {
		u := r.u
		docs := append(managedDocs(ad, u.Attached), inlineDocs(u.Inline)...)
		for _, gn := range u.Groups {
			g := groups[gn]
			for _, d := range append(managedDocs(ad, g.Attached), inlineDocs(g.Inline)...) {
				d.Name += " via group " + gn
				docs = append(docs, d)
			}
		}
		g := EvaluateInvoke(docs)
		if g.Allowed && boundaryBlocks(ad, u.Boundary) {
			g = Grant{}
		}
		if r.err != nil {
			rep.Warnings = append(rep.Warnings, "user "+u.UserName+": access keys: "+r.err.Error())
		}
		var active []KeyInfo
		for _, k := range r.keys {
			ki := KeyInfo{k.ID, k.Status, k.CreateDate, k.LastUsed, k.LastSvc, k.LastRegion}
			if k.Status == "Active" {
				active = append(active, ki)
				rep.Stats["active_keys"]++
			}
		}
		if g.Allowed {
			rep.Principals = append(rep.Principals, &Principal{Type: "user", Name: u.UserName, Arn: u.Arn, Via: g.Via, Conditional: g.Conditional, Keys: active})
		}
		for _, k := range active {
			res := "user " + u.UserName + " · key " + maskKey(k.ID)
			var ctxt []string
			ctxt = append(ctxt, fmt.Sprintf("created %s (%dd)", k.Created.Format("2006-01-02"), days(k.Created)))
			dormant := false
			if k.LastUsed.IsZero() {
				ctxt = append(ctxt, "never used")
				dormant = days(k.Created) >= 7
			} else {
				ctxt = append(ctxt, fmt.Sprintf("last used %s (%dd ago, %s %s)", k.LastUsed.Format("2006-01-02"), days(k.LastUsed), k.LastSvc, k.LastRegion))
				dormant = days(k.LastUsed) >= o.DormantDays
			}
			tail := " · " + strings.Join(ctxt, " · ")
			deactivate := fmt.Sprintf("aws iam update-access-key --user-name %s --access-key-id %s --status Inactive  (then delete after a quiet week)", u.UserName, k.ID)
			cond := ""
			if g.Conditional {
				cond = " (only under a Condition - check it)"
			}
			switch {
			case g.Allowed && dormant:
				add(sev.Critical, "KEY_BEDROCK_DORMANT", res,
					"dormant long-lived access key that can invoke Bedrock"+cond+" via "+strings.Join(g.Via, ", ")+""+tail, deactivate)
			case g.Allowed:
				sv := sev.High
				if g.Conditional {
					sv = sev.Medium
				}
				add(sv, "KEY_BEDROCK", res,
					"long-lived access key can invoke Bedrock"+cond+" via "+strings.Join(g.Via, ", ")+tail,
					"move this workload to an IAM role (or Identity Center); if a key must stay, scope bedrock:Invoke* to specific model ARNs and add an aws:SourceIp condition")
			case dormant:
				add(sev.Low, "KEY_DORMANT", res, "dormant long-lived access key"+tail, deactivate)
			}
			if days(k.Created) >= o.OldKeyDays && !dormant && g.Allowed {
				// age already shown in tail; rotation hint only
				rep.Stats["old_bedrock_keys"]++
			}
		}
	}

	// Roles.
	for _, rl := range ad.Roles {
		if strings.HasPrefix(rl.Path, "/aws-service-role/") {
			continue
		}
		docs := append(managedDocs(ad, rl.Attached), inlineDocs(rl.Inline)...)
		g := EvaluateInvoke(docs)
		if g.Allowed && boundaryBlocks(ad, rl.Boundary) {
			g = Grant{}
		}
		if !g.Allowed {
			continue
		}
		risk, who := TrustRisk(rl.Trust, rep.Account)
		p := &Principal{Type: "role", Name: rl.RoleName, Arn: rl.Arn, Via: g.Via, Conditional: g.Conditional, RoleLastUse: rl.LastUsed, Trust: risk, TrustWho: who}
		rep.Principals = append(rep.Principals, p)
		orgOnly := risk == "external" && rep.OrgMgmt != ""
		for _, w := range who {
			if !strings.Contains(w, rep.OrgMgmt) || rep.OrgMgmt == "" {
				orgOnly = false
			}
		}
		switch {
		case risk == "public":
			add(sev.Critical, "ROLE_BEDROCK_PUBLIC_TRUST", "role "+rl.RoleName,
				"role can invoke Bedrock and its trust policy allows ANY AWS principal (\"*\") without a condition", "restrict the trust policy Principal to your own accounts")
		case orgOnly:
			p.Trust = "org-mgmt"
			add(sev.Info, "ROLE_ORG_MANAGEMENT_TRUST", "role "+rl.RoleName,
				"assumable by your AWS Organizations management account ("+rep.OrgMgmt+") - expected for "+rl.RoleName+"; anyone with admin there can invoke Bedrock here", "")
		case risk == "external":
			hint := "confirm the vendor; require sts:ExternalId in the trust policy"
			if rl.RoleName == "OrganizationAccountAccessRole" {
				hint = "likely your Organizations management account - verify: aws organizations describe-organization --query Organization.MasterAccountId"
			}
			add(sev.High, "ROLE_BEDROCK_EXTERNAL_TRUST", "role "+rl.RoleName,
				"role can invoke Bedrock and is assumable by another account without a condition: "+strings.Join(who, ", "), hint)
		}
		// Workload roles (EC2 / CI / Lambda / ECS) with blanket admin: any job on that compute can call Bedrock.
		if risk == "" && !g.Conditional && broadAdmin(g.Via) {
			for _, svc := range TrustServices(rl.Trust) {
				if svc == "ec2.amazonaws.com" || svc == "ecs-tasks.amazonaws.com" || svc == "lambda.amazonaws.com" || svc == "codebuild.amazonaws.com" {
					last := "never assumed"
					if !rl.LastUsed.IsZero() {
						last = "last assumed " + rl.LastUsed.Format("2006-01-02")
					}
					add(sev.Medium, "ROLE_WORKLOAD_ADMIN", "role "+rl.RoleName,
						"workload role for "+svc+" has "+strings.Join(g.Via, ", ")+" - any code running there (e.g. a CI job) can invoke Bedrock and enable models in any region · "+last,
						"scope it down; at minimum deny bedrock:* via a permissions boundary or SCP if this workload doesn't need it")
					break
				}
			}
		}
	}
	sort.Slice(rep.Principals, func(i, j int) bool {
		if rep.Principals[i].Type != rep.Principals[j].Type {
			return rep.Principals[i].Type > rep.Principals[j].Type // users first
		}
		return rep.Principals[i].Name < rep.Principals[j].Name
	})
}

func maskKey(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:4] + "..." + id[len(id)-4:]
}

func auditUsage(ctx context.Context, c *Client, rep *Report, o Options, now time.Time,
	add func(sev.Severity, string, string, string, string)) {
	start := now.Add(-time.Duration(o.UsageDays) * 24 * time.Hour)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, o.Concurrency)
	denied := 0
	var unreachable []string
	for _, region := range o.Regions {
		wg.Add(1)
		sem <- struct{}{}
		go func(region string) {
			defer wg.Done()
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			models, err := c.BedrockModelsWithTraffic(rctx, region)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case IsRegionDisabled(err):
				case rctx.Err() != nil || strings.Contains(err.Error(), "deadline exceeded") || strings.Contains(err.Error(), "no such host"):
					unreachable = append(unreachable, region)
				case IsAccessDenied(err):
					denied++
				default:
					rep.Warnings = append(rep.Warnings, region+": cloudwatch:ListMetrics: "+err.Error())
				}
				return
			}
			if len(models) == 0 {
				return
			}
			ru := &RegionUsage{Region: region}
			for _, m := range models {
				mu2 := ModelUsage{Model: m}
				mu2.Invocations, mu2.LastSeen, _ = c.BedrockSum(ctx, region, "Invocations", m, start, now)
				mu2.InputTokens, _, _ = c.BedrockSum(ctx, region, "InputTokenCount", m, start, now)
				mu2.OutputTokens, _, _ = c.BedrockSum(ctx, region, "OutputTokenCount", m, start, now)
				if mu2.Invocations > 0 {
					ru.Models = append(ru.Models, mu2)
				}
			}
			if len(ru.Models) == 0 {
				return
			}
			sort.Slice(ru.Models, func(i, j int) bool { return ru.Models[i].Invocations > ru.Models[j].Invocations })
			if on, err := c.InvocationLoggingEnabled(ctx, region); err == nil {
				ru.Logging = &on
			}
			mu.Lock()
			rep.Regions = append(rep.Regions, ru)
			mu.Unlock()
		}(region)
	}
	wg.Wait()
	if len(unreachable) > 0 {
		sort.Strings(unreachable)
		rep.Warnings = append(rep.Warnings, "no answer from "+strings.Join(unreachable, ", ")+" - usually an opt-in region not enabled for this account; Bedrock usage there is unknown")
	}
	if denied > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("cloudwatch:ListMetrics denied in %d region(s) - Bedrock usage there is unknown (needs CloudWatchReadOnlyAccess)", denied))
	}
	sort.Slice(rep.Regions, func(i, j int) bool { return rep.Regions[i].Region < rep.Regions[j].Region })

	expected := map[string]bool{}
	for _, r := range o.ExpectedRegions {
		expected[r] = true
	}
	for _, ru := range rep.Regions {
		var total float64
		var names []string
		for _, m := range ru.Models {
			total += m.Invocations
			names = append(names, m.Model)
		}
		msg := fmt.Sprintf("%.0f invocations in %dd: %s", total, o.UsageDays, strings.Join(names, ", "))
		if len(expected) > 0 && !expected[ru.Region] {
			add(sev.High, "BEDROCK_UNEXPECTED_REGION", "region "+ru.Region, "Bedrock used outside your expected regions - "+msg,
				"if this isn't you: find the caller in CloudTrail (eventSource bedrock.amazonaws.com) and deactivate its credentials")
		} else {
			add(sev.Info, "BEDROCK_USAGE", "region "+ru.Region, msg, "")
		}
		if ru.Logging != nil && !*ru.Logging {
			add(sev.Low, "BEDROCK_LOGGING_OFF", "region "+ru.Region, "model invocation logging is off - after an incident you won't see prompts or callers",
				"enable it: Bedrock console -> Settings -> Model invocation logging")
		}
	}
	if len(expected) == 0 && len(rep.Regions) >= 3 {
		var rs []string
		for _, ru := range rep.Regions {
			rs = append(rs, ru.Region)
		}
		add(sev.Medium, "BEDROCK_MANY_REGIONS", "account", "Bedrock used in "+fmt.Sprint(len(rs))+" regions ("+strings.Join(rs, ", ")+")",
			"rerun with --expected-regions to flag the unexpected ones; consider an SCP denying bedrock:* outside them")
	}
}

func broadAdmin(via []string) bool {
	for _, v := range via {
		if strings.HasPrefix(v, "AdministratorAccess") || strings.HasPrefix(v, "PowerUserAccess") {
			return true
		}
	}
	return false
}
