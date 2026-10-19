// billfuse - a circuit breaker for AI API spend. This build ships only the
// read-only audit: `billfuse audit gcp`.
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

	"github.com/jhelbling/billfuse/internal/gcp"
)

var version = "0.5.0"

const usage = `billfuse %s - circuit breaker for AI API spend

Usage:
  billfuse audit gcp [flags]     read-only audit of billing accounts, projects and API keys
  billfuse audit aws [flags]     read-only audit of who can invoke Bedrock, access keys, Bedrock usage by region
  billfuse watch gcp|aws [flags] near-real-time spend watch: $/hour estimates, alerts, optional kill switch
  billfuse demo                  run everything against built-in fake accounts (no credentials)
  billfuse version

Run "billfuse <command> <cloud> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(64)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("billfuse", version)
	case "demo":
		os.Exit(runDemo(os.Stdout, os.Stderr))
	case "watch":
		os.Exit(runWatch(os.Args[2:], os.Stdout, os.Stderr))
	case "audit":
		if len(os.Args) >= 3 && os.Args[2] == "gcp" {
			os.Exit(runAuditGCP(os.Args[3:], os.Stdout, os.Stderr))
		}
		if len(os.Args) >= 3 && os.Args[2] == "aws" {
			os.Exit(runAuditAWS(os.Args[3:], os.Stdout, os.Stderr))
		}
		fmt.Fprintln(os.Stderr, "usage: billfuse audit gcp|aws [flags]")
		os.Exit(64)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(64)
	}
}

type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*m = append(*m, s)
		}
	}
	return nil
}

func runAuditGCP(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit gcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var bas, projects multi
	fs.Var(&bas, "billing-account", "billing account ID(s) to audit (default: all you can see); repeatable or comma-separated")
	fs.Var(&projects, "project", "extra project ID(s) to audit even if billing listing is denied")
	asJSON := fs.Bool("json", false, "print JSON report")
	failOn := fs.String("fail-on", "high", "exit 2 if any finding is at/above this severity: info|low|medium|high|critical|none")
	minShow := fs.String("min-severity", "low", "hide findings below this severity in text output")
	token := fs.String("token", "", "OAuth access token (default: $BILLFUSE_ACCESS_TOKEN, then gcloud, then metadata server)")
	quota := fs.String("quota-project", "", "project to charge API quota to (x-goog-user-project), needed for some ADC user creds")
	recent := fs.Int("recent-days", 30, "flag billed projects created within this many days")
	usageDays := fs.Int("usage-days", 30, "look-back for per-key usage from Cloud Monitoring (max 42)")
	noUsage := fs.Bool("no-usage", false, "skip the per-key usage query")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall timeout")
	fs.Usage = func() { fmt.Fprintf(stderr, usage, version); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 64
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	tok, src, err := resolveToken(ctx, *token)
	if err != nil {
		fmt.Fprintln(stderr, "auth:", err)
		return 1
	}
	c := &gcp.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Token: tok, E: endpointsFromEnv(), QuotaProj: *quota}

	if !*asJSON {
		fmt.Fprintf(stderr, "billfuse %s · read-only audit · auth via %s\n", version, src)
	}
	rep, err := gcp.Audit(ctx, c, gcp.Options{BillingAccounts: bas, Projects: projects, RecentDays: *recent, UsageDays: *usageDays, NoUsage: *noUsage})
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		if m := err.Error(); strings.Contains(m, "has been deleted") || strings.Contains(strings.ToLower(m), "quota project") {
			fmt.Fprintln(stderr, "hint: the quota project is missing or deleted. Run without --quota-project, or pick a live one:\n  gcloud projects list --format='value(projectId)'\n  gcloud config set project <ID> && billfuse audit gcp --quota-project <ID>")
		}
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		min, ok := gcp.ParseSeverity(*minShow)
		if !ok {
			min = gcp.Low
		}
		renderText(stdout, rep, min)
	}

	if strings.EqualFold(*failOn, "none") {
		return 0
	}
	th, ok := gcp.ParseSeverity(*failOn)
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

func endpointsFromEnv() gcp.Endpoints {
	e := gcp.DefaultEndpoints()
	if v := os.Getenv("BILLFUSE_GCP_ENDPOINT"); v != "" { // test hook: one fake server for all APIs
		e = gcp.Endpoints{Billing: v, ResourceManager: v, ServiceUsage: v, APIKeys: v, Monitoring: v}
	}
	return e
}

// resolveToken: explicit flag -> env -> gcloud (user, then ADC) -> GCE/Cloud Run metadata server.
func resolveToken(ctx context.Context, flagTok string) (string, string, error) {
	if flagTok != "" {
		return flagTok, "--token", nil
	}
	if t := os.Getenv("BILLFUSE_ACCESS_TOKEN"); t != "" {
		return t, "$BILLFUSE_ACCESS_TOKEN", nil
	}
	if _, err := exec.LookPath("gcloud"); err == nil {
		for _, a := range [][]string{{"auth", "print-access-token"}, {"auth", "application-default", "print-access-token"}} {
			c := exec.CommandContext(ctx, "gcloud", a...)
			c.Stderr = io.Discard
			if out, err := c.Output(); err == nil {
				if t := strings.TrimSpace(string(out)); t != "" {
					return t, "gcloud " + strings.Join(a, " "), nil
				}
			}
		}
	}
	mctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(mctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		defer resp.Body.Close()
		var r struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&r) == nil && r.AccessToken != "" {
			return r.AccessToken, "metadata server", nil
		}
	}
	return "", "", errors.New("no credentials: run `gcloud auth login`, or set BILLFUSE_ACCESS_TOKEN, or pass --token")
}

func renderText(w io.Writer, rep *gcp.Report, min gcp.Severity) {
	fmt.Fprintf(w, "\nBILLING ACCOUNTS (%d)\n", len(rep.BillingAccounts))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, b := range rep.BillingAccounts {
		state := "open"
		if !b.Open {
			state = "closed"
		}
		n, billed := 0, 0
		id := strings.TrimPrefix(b.Name, "billingAccounts/")
		for _, p := range rep.Projects {
			if p.BillingAccount == id {
				n++
				if p.BillingEnabled {
					billed++
				}
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%d projects (%d billed)\n", id, b.DisplayName, state, n, billed)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nPROJECTS (%d)\n", len(rep.Projects))
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  PROJECT\tBILLING ACCT\tBILLED\tVISIBLE\tPAID KEY-CALLABLE APIS\tKEYS (risky)")
	for _, p := range rep.Projects {
		ai := "-"
		if all := append(append([]string{}, p.AIServices...), p.KeyBillable...); len(all) > 0 {
			var short []string
			for _, s := range all {
				short = append(short, svcLabel(s))
			}
			ai = strings.Join(short, ", ")
		}
		vis := "yes"
		if !p.Visible {
			vis = "NO"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%v\t%s\t%s\t%d (%d)\n", p.ProjectID, dash(p.BillingAccount), p.BillingEnabled, vis, ai, p.KeysTotal, p.KeysRisky)
	}
	tw.Flush()

	if len(rep.Keys) > 0 {
		fmt.Fprintf(w, "\nAPI KEYS (%d)\n", len(rep.Keys))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		hdr := "  PROJECT\tKEY\tCREATED\tAPI RESTRICTION\tAPP RESTR."
		if rep.UsageDays > 0 {
			hdr += fmt.Sprintf("\tREQUESTS %dd\tLAST USED\tUSED FOR", rep.UsageDays)
		}
		fmt.Fprintln(tw, hdr)
		for _, k := range rep.Keys {
			restr := "NONE"
			if k.Restricted {
				var t []string
				for _, s := range k.Targets {
					t = append(t, svcLabel(s))
				}
				restr = strings.Join(t, ", ")
				if len(restr) > 40 {
					restr = restr[:37] + "..."
				}
			}
			app := "no"
			if k.AppRestrict {
				app = "yes"
			}
			name := k.DisplayName
			if name == "" {
				name = k.ID
			}
			created := "-"
			if !k.CreateTime.IsZero() {
				created = k.CreateTime.Format("2006-01-02")
			}
			line := fmt.Sprintf("  %s\t%s\t%s\t%s\t%s", k.Project, name, created, restr, app)
			if rep.UsageDays > 0 {
				if !k.UsageKnown {
					line += "\t?\t?\t?"
				} else if k.Requests == 0 {
					line += "\t0\tnever\t-"
				} else {
					var u []string
					for _, s := range k.UsedServices {
						u = append(u, svcLabel(s))
					}
					line += fmt.Sprintf("\t%d\t%s\t%s", k.Requests, k.LastUsed.Format("2006-01-02"), strings.Join(u, ", "))
				}
			}
			fmt.Fprintln(tw, line)
		}
		tw.Flush()
	}

	count := map[gcp.Severity]int{}
	shown := 0
	fmt.Fprintln(w, "\nFINDINGS")
	for _, f := range rep.Findings {
		count[f.Severity]++
		if f.Severity < min {
			continue
		}
		shown++
		loc := f.Project
		if loc == "" {
			loc = "billingAccounts/" + f.BillingAccount
		}
		if f.Resource != "" {
			loc += " · key " + f.Resource
		}
		fmt.Fprintf(w, "  [%-8s] %s  %s\n             %s\n", f.Severity, f.Code, loc, f.Message)
		if f.Fix != "" {
			fmt.Fprintf(w, "             fix: %s\n", f.Fix)
		}
	}
	if shown == 0 {
		fmt.Fprintln(w, "  none at or above", min)
	}

	var warn []string
	warn = append(warn, rep.Warnings...)
	for _, p := range rep.Projects {
		for _, x := range p.Warnings {
			warn = append(warn, p.ProjectID+": "+x)
		}
	}
	if len(warn) > 0 {
		fmt.Fprintf(w, "\nCOULD NOT CHECK (%d) - missing permissions leave blind spots\n", len(warn))
		for _, x := range warn {
			fmt.Fprintln(w, "  -", x)
		}
	}
	fmt.Fprintf(w, "\nSUMMARY  critical %d · high %d · medium %d · low %d · info %d\n",
		count[gcp.Critical], count[gcp.High], count[gcp.Medium], count[gcp.Low], count[gcp.Info])
	fmt.Fprintln(w, "This audit only reads. Nothing was changed.")
}

func svcLabel(s string) string {
	if n, ok := gcp.AIServices[s]; ok {
		return n
	}
	if n, ok := gcp.KeyBillableServices[s]; ok {
		return n
	}
	return strings.TrimSuffix(s, ".googleapis.com")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
