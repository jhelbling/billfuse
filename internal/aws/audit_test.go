package aws

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jhelbling/billfuse/internal/awsfake"
	"github.com/jhelbling/billfuse/internal/sev"
)

func TestEvaluateInvoke(t *testing.T) {
	cases := []struct {
		doc         string
		allowed     bool
		conditional bool
	}{
		{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, true, false},
		{`{"Statement":{"Effect":"Allow","Action":"bedrock:Invoke*","Resource":"arn:aws:bedrock:*::foundation-model/*"}}`, true, false},
		{`{"Statement":[{"Effect":"Allow","Action":"bedrock:ListFoundationModels","Resource":"*"}]}`, false, false},
		{`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`, true, false},
		{`{"Statement":[{"Effect":"Allow","NotAction":"bedrock:*","Resource":"*"}]}`, false, false},
		{`{"Statement":[{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, true, true},
		{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"bedrock:*","Resource":"*"}]}`, false, false},
		{`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, false, false},
	}
	for i, c := range cases {
		g := EvaluateInvoke([]NamedDoc{{"p", c.doc}})
		if g.Allowed != c.allowed || g.Conditional != c.conditional {
			t.Errorf("case %d: got %+v, want allowed=%v conditional=%v", i, g, c.allowed, c.conditional)
		}
	}
}

func TestAudit(t *testing.T) {
	srv := awsfake.New(t)
	defer srv.Close()
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	c := &Client{HTTP: srv.Client(), Creds: Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "s"}, Endpoint: awsfake.Endpoint(srv.URL)}
	rep, err := Audit(context.Background(), c, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]sev.Severity{}
	for _, f := range rep.Findings {
		got[f.Code+"|"+f.Resource] = f.Severity
	}
	want := map[string]sev.Severity{
		"ROOT_ACCESS_KEY|root":                                         sev.Critical,
		"KEY_BEDROCK_DORMANT|user ci-bot · key AKIA...0001":            sev.Critical,
		"KEY_BEDROCK|user ml-app · key AKIA...0002":                    sev.High,
		"KEY_BEDROCK|user office · key AKIA...0004":                    sev.Medium,
		"KEY_DORMANT|user reports · key AKIA...0003":                   sev.Low,
		"ROLE_BEDROCK_PUBLIC_TRUST|role open-door":                     sev.Critical,
		"ROLE_BEDROCK_EXTERNAL_TRUST|role vendor-analytics":            sev.High,
		"BEDROCK_USAGE|region us-east-1":                               sev.Info,
		"BEDROCK_USAGE|region ap-south-2":                              sev.Info,
		"BEDROCK_LOGGING_OFF|region ap-south-2":                        sev.Low,
		"ROLE_ORG_MANAGEMENT_TRUST|role OrganizationAccountAccessRole": sev.Info,
		"ROLE_WORKLOAD_ADMIN|role gitlab-runner":                       sev.Medium,
	}
	for k, s := range want {
		if g, ok := got[k]; !ok || g != s {
			t.Errorf("finding %q: got %v present=%v, want %v", k, g, ok, s)
		}
	}
	for k := range got {
		if strings.Contains(k, "blocked") || strings.Contains(k, "summarizer") {
			t.Errorf("unexpected finding %q", k)
		}
	}
	var names []string
	for _, p := range rep.Principals {
		names = append(names, p.Type+":"+p.Name)
	}
	if strings.Join(names, ",") != "user:ci-bot,user:ml-app,user:office,role:OrganizationAccountAccessRole,role:gitlab-runner,role:open-door,role:summarizer-lambda,role:vendor-analytics" {
		t.Errorf("principals = %v", names)
	}
	if len(rep.Regions) != 2 || rep.Regions[0].Region != "ap-south-2" || rep.Regions[0].Models[0].Invocations != 48000 {
		t.Errorf("regions = %+v", rep.Regions)
	}
	slow := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "me-central-1") {
			t.Errorf("disabled region should be silent: %s", w)
		}
		if strings.Contains(w, "no answer from me-south-1") {
			slow = true
		}
	}
	if !slow {
		t.Errorf("hanging region should be reported once as unreachable: %v", rep.Warnings)
	}
	if rep.OrgMgmt != "222222222222" {
		t.Errorf("org mgmt = %q", rep.OrgMgmt)
	}

	// expected regions -> ap-south-2 becomes HIGH
	rep, _ = Audit(context.Background(), c, Options{Now: func() time.Time { return now }, ExpectedRegions: []string{"us-east-1"}, Regions: []string{"us-east-1", "ap-south-2"}})
	found := false
	for _, f := range rep.Findings {
		if f.Code == "BEDROCK_UNEXPECTED_REGION" && f.Resource == "region ap-south-2" && f.Severity == sev.High {
			found = true
		}
	}
	if !found {
		t.Error("expected BEDROCK_UNEXPECTED_REGION for ap-south-2")
	}
}

func TestTrustRisk(t *testing.T) {
	if r, _ := TrustRisk(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}`, "111111111111"); r != "" {
		t.Errorf("own account should be fine, got %q", r)
	}
	if r, _ := TrustRisk(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}}]}`, "111111111111"); r != "" {
		t.Errorf("external with ExternalId should be fine, got %q", r)
	}
	if r, _ := TrustRisk(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`, "1"); r != "public" {
		t.Errorf("want public, got %q", r)
	}
}
