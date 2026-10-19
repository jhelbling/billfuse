package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	awsaudit "github.com/jhelbling/billfuse/internal/aws"
	"github.com/jhelbling/billfuse/internal/sev"
)

func runAuditAWS(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit aws", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var regions, expected multi
	profile := fs.String("profile", os.Getenv("AWS_PROFILE"), "AWS CLI profile (default: $AWS_PROFILE / default chain)")
	fs.Var(&regions, "regions", "regions to scan for Bedrock usage (default: all Bedrock regions)")
	fs.Var(&expected, "expected-regions", "regions where you expect Bedrock use; usage elsewhere is HIGH")
	asJSON := fs.Bool("json", false, "print JSON report")
	failOn := fs.String("fail-on", "high", "exit 2 if any finding is at/above this severity: info|low|medium|high|critical|none")
	minShow := fs.String("min-severity", "low", "hide findings below this severity in text output")
	dormant := fs.Int("dormant-days", 90, "access key unused this many days counts as dormant")
	usageDays := fs.Int("usage-days", 30, "CloudWatch look-back for Bedrock usage")
	noUsage := fs.Bool("no-usage", false, "skip the per-region Bedrock usage scan")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	creds, src, err := resolveAWSCreds(ctx, *profile)
	if err != nil {
		fmt.Fprintln(stderr, "auth:", err)
		return 1
	}
	ep := awsaudit.Endpoint(awsaudit.DefaultEndpoint)
	if v := os.Getenv("BILLFUSE_AWS_ENDPOINT"); v != "" {
		ep = func(service, region string) string { return v + "/" + service + "/" + region }
	}
	c := &awsaudit.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Creds: creds, Endpoint: ep}
	if !*asJSON {
		fmt.Fprintf(stderr, "billfuse %s · read-only audit · auth via %s\n", version, src)
	}
	rep, err := awsaudit.Audit(ctx, c, awsaudit.Options{Regions: regions, ExpectedRegions: expected,
		DormantDays: *dormant, UsageDays: *usageDays, NoUsage: *noUsage})
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		min, ok := sev.Parse(*minShow)
		if !ok {
			min = sev.Low
		}
		renderAWS(stdout, rep, min)
	}
	if strings.EqualFold(*failOn, "none") {
		return 0
	}
	th, ok := sev.Parse(*failOn)
	if !ok {
		fmt.Fprintln(stderr, "bad --fail-on value:", *failOn)
		return 64
	}
	for _, f := range rep.Findings {
		if f.Severity >= th {
			return 2
		}
	}
	return 0
}

// resolveAWSCreds: env vars -> `aws configure export-credentials` (handles SSO, roles, profiles).
func resolveAWSCreds(ctx context.Context, profile string) (awsaudit.Credentials, string, error) {
	if profile == "" && os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		return awsaudit.Credentials{
			AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		}, "environment", nil
	}
	if _, err := exec.LookPath("aws"); err != nil {
		return awsaudit.Credentials{}, "", errors.New("no AWS credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or install AWS CLI v2 and run `aws login` / `aws sso login`")
	}
	a := []string{"configure", "export-credentials", "--format", "process"}
	if profile != "" {
		a = append(a, "--profile", profile)
	}
	cmd := exec.CommandContext(ctx, "aws", a...)
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		return awsaudit.Credentials{}, "", fmt.Errorf("aws configure export-credentials failed: %s (run `aws sso login` / `aws login`, or pass --profile)", strings.TrimSpace(errb.String()))
	}
	var c awsaudit.Credentials
	if err := json.Unmarshal(out, &c); err != nil || c.AccessKeyID == "" {
		return awsaudit.Credentials{}, "", errors.New("could not parse credentials from aws CLI")
	}
	src := "aws CLI"
	if profile != "" {
		src += " profile " + profile
	}
	return c, src, nil
}

func renderAWS(w io.Writer, rep *awsaudit.Report, min sev.Severity) {
	fmt.Fprintf(w, "\nACCOUNT %s  (caller %s)\n", rep.Account, rep.Caller)
	if rep.OrgMgmt != "" {
		fmt.Fprintf(w, "  organization management account: %s\n", rep.OrgMgmt)
	}
	fmt.Fprintf(w, "  %d users · %d roles · %d active access keys\n", rep.Stats["users"], rep.Stats["roles"], rep.Stats["active_keys"])

	fmt.Fprintf(w, "\nWHO CAN INVOKE BEDROCK (%d)\n", len(rep.Principals))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  TYPE\tNAME\tVIA\tACCESS KEYS / LAST USE\tTRUST")
	for _, p := range rep.Principals {
		via := strings.Join(p.Via, ", ")
		if p.Conditional {
			via += " [conditional]"
		}
		if len(via) > 48 {
			via = via[:45] + "..."
		}
		use := "-"
		if p.Type == "user" {
			var ks []string
			for _, k := range p.Keys {
				lu := "never used"
				if !k.LastUsed.IsZero() {
					lu = "used " + k.LastUsed.Format("2006-01-02")
				}
				ks = append(ks, fmt.Sprintf("%s...%s (%s)", k.ID[:4], k.ID[len(k.ID)-4:], lu))
			}
			if len(ks) > 0 {
				use = strings.Join(ks, "; ")
			} else {
				use = "no active keys"
			}
		} else if !p.RoleLastUse.IsZero() {
			use = "assumed " + p.RoleLastUse.Format("2006-01-02")
		}
		trust := "-"
		if p.Trust != "" {
			trust = strings.ToUpper(p.Trust)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", p.Type, p.Name, via, use, trust)
	}
	tw.Flush()

	if rep.UsageDays > 0 {
		fmt.Fprintf(w, "\nBEDROCK USAGE BY REGION (last %dd)\n", rep.UsageDays)
		if len(rep.Regions) == 0 {
			fmt.Fprintln(w, "  no Bedrock invocations found")
		}
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if len(rep.Regions) > 0 {
			fmt.Fprintln(tw, "  REGION\tMODEL\tINVOCATIONS\tINPUT TOK\tOUTPUT TOK\tLAST DAY\tLOGGING")
			for _, r := range rep.Regions {
				lg := "?"
				if r.Logging != nil {
					lg = map[bool]string{true: "on", false: "OFF"}[*r.Logging]
				}
				for _, m := range r.Models {
					fmt.Fprintf(tw, "  %s\t%s\t%.0f\t%s\t%s\t%s\t%s\n", r.Region, m.Model, m.Invocations, human(m.InputTokens), human(m.OutputTokens), m.LastSeen.Format("2006-01-02"), lg)
				}
			}
		}
		tw.Flush()
	}

	count := map[sev.Severity]int{}
	shown := 0
	fmt.Fprintln(w, "\nFINDINGS")
	for _, f := range rep.Findings {
		count[f.Severity]++
		if f.Severity < min {
			continue
		}
		shown++
		fmt.Fprintf(w, "  [%-8s] %s  %s\n             %s\n", f.Severity, f.Code, f.Resource, f.Message)
		if f.Fix != "" {
			fmt.Fprintf(w, "             fix: %s\n", f.Fix)
		}
	}
	if shown == 0 {
		fmt.Fprintln(w, "  none at or above", min)
	}
	if len(rep.Warnings) > 0 {
		fmt.Fprintf(w, "\nCOULD NOT CHECK (%d) - missing permissions leave blind spots\n", len(rep.Warnings))
		for _, x := range rep.Warnings {
			fmt.Fprintln(w, "  -", x)
		}
	}
	fmt.Fprintf(w, "\nSUMMARY  critical %d · high %d · medium %d · low %d · info %d\n",
		count[sev.Critical], count[sev.High], count[sev.Medium], count[sev.Low], count[sev.Info])
	fmt.Fprintln(w, "This audit only reads. Nothing was changed.")
}

func human(f float64) string {
	switch {
	case f >= 1e9:
		return fmt.Sprintf("%.1fB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1fk", f/1e3)
	}
	return fmt.Sprintf("%.0f", f)
}
