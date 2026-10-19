package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	awsc "github.com/jhelbling/billfuse/internal/aws"
	"github.com/jhelbling/billfuse/internal/gcp"
	"github.com/jhelbling/billfuse/internal/sev"
	"github.com/jhelbling/billfuse/internal/watch"
)

type watchFlags struct {
	interval, window, delay, cooldown time.Duration
	maxHourly, maxDaily, maxRPM       float64
	spike, spikeFloor                 float64
	warmup                            int
	expected                          multi
	notifyMin                         string
	slack, tgToken, tgChat            string
	webhook, ntfy, heartbeat          string
	statePath, prices                 string
	act, once, asJSON, testAlert      bool
}

func commonWatchFlags(fs *flag.FlagSet, defDelay time.Duration) *watchFlags {
	w := &watchFlags{}
	fs.DurationVar(&w.interval, "interval", time.Minute, "poll interval")
	fs.DurationVar(&w.window, "window", 10*time.Minute, "usage window evaluated each cycle")
	fs.DurationVar(&w.delay, "delay", defDelay, "skip the most recent metrics (ingestion delay)")
	fs.DurationVar(&w.cooldown, "cooldown", 30*time.Minute, "repeat a still-firing alert at most this often")
	fs.Float64Var(&w.maxHourly, "max-hourly", 25, "CRITICAL + kill switch when est. $/hour per project/account exceeds this (0=off)")
	fs.Float64Var(&w.maxDaily, "max-daily", 250, "CRITICAL + kill switch when est. $ since 00:00 UTC exceeds this (0=off)")
	fs.Float64Var(&w.maxRPM, "max-rpm", 0, "HIGH when AI requests/minute exceed this (0=off)")
	fs.Float64Var(&w.spike, "spike", 5, "HIGH when $/hour exceeds Nx the learned baseline (0=off)")
	fs.Float64Var(&w.spikeFloor, "spike-floor", 2, "ignore spikes below this $/hour")
	fs.IntVar(&w.warmup, "warmup", 5, "cycles to learn before spike/new-model/new-region alerts")
	fs.Var(&w.expected, "expected-regions", "regions where AI use is expected; others alert HIGH")
	fs.StringVar(&w.notifyMin, "notify-min", "medium", "minimum severity sent to channels: info|low|medium|high|critical")
	fs.StringVar(&w.slack, "slack", os.Getenv("BILLFUSE_SLACK_WEBHOOK"), "Slack incoming-webhook URL ($BILLFUSE_SLACK_WEBHOOK)")
	fs.StringVar(&w.tgToken, "telegram-token", os.Getenv("BILLFUSE_TELEGRAM_TOKEN"), "Telegram bot token ($BILLFUSE_TELEGRAM_TOKEN)")
	fs.StringVar(&w.tgChat, "telegram-chat", os.Getenv("BILLFUSE_TELEGRAM_CHAT"), "Telegram chat id ($BILLFUSE_TELEGRAM_CHAT)")
	fs.StringVar(&w.webhook, "webhook", os.Getenv("BILLFUSE_WEBHOOK"), "generic JSON webhook URL ($BILLFUSE_WEBHOOK)")
	fs.StringVar(&w.ntfy, "ntfy", os.Getenv("BILLFUSE_NTFY"), "ntfy topic URL for phone push, e.g. https://ntfy.sh/<secret> ($BILLFUSE_NTFY)")
	fs.StringVar(&w.heartbeat, "heartbeat", os.Getenv("BILLFUSE_HEARTBEAT"), "dead-man's-switch URL pinged every cycle, e.g. healthchecks.io ($BILLFUSE_HEARTBEAT)")
	fs.StringVar(&w.statePath, "state", "", "state file (default ~/.billfuse/watch-<cloud>.json)")
	fs.StringVar(&w.prices, "prices", "", "JSON file overriding model prices")
	fs.BoolVar(&w.act, "act", false, "REALLY trip the kill switch on CRITICAL (default: dry-run, only says what it would do)")
	fs.BoolVar(&w.once, "once", false, "run one cycle and exit (for cron / Cloud Run jobs / Lambda); exit 2 if CRITICAL")
	fs.BoolVar(&w.asJSON, "json", false, "print each cycle as JSON")
	fs.BoolVar(&w.testAlert, "test-alert", false, "send a test message to all channels and exit")
	return w
}

func (w *watchFlags) notifiers() []watch.Notifier {
	var ns []watch.Notifier
	if w.slack != "" {
		ns = append(ns, watch.Slack{URL: w.slack})
	}
	if w.tgToken != "" && w.tgChat != "" {
		ns = append(ns, watch.Telegram{Token: w.tgToken, ChatID: w.tgChat})
	}
	if w.webhook != "" {
		ns = append(ns, watch.Webhook{URL: w.webhook})
	}
	if w.ntfy != "" {
		ns = append(ns, watch.Ntfy{URL: w.ntfy})
	}
	return ns
}

func (w *watchFlags) config(cloud string, col watch.Collector, actor watch.Actor, stderr io.Writer) (*watch.Config, error) {
	min, ok := sev.Parse(w.notifyMin)
	if !ok {
		return nil, fmt.Errorf("bad --notify-min %q", w.notifyMin)
	}
	path := w.statePath
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".billfuse", "watch-"+cloud+".json")
	}
	exp := map[string]bool{}
	for _, r := range w.expected {
		exp[r] = true
	}
	return &watch.Config{
		Collector: col, Actor: actor, Notifiers: w.notifiers(),
		Limits: watch.Limits{MaxHourly: w.maxHourly, MaxDaily: w.maxDaily, MaxRPM: w.maxRPM,
			SpikeFactor: w.spike, SpikeFloor: w.spikeFloor, Warmup: w.warmup, Expected: exp},
		Interval: w.interval, Window: w.window, Delay: w.delay, Cooldown: w.cooldown,
		MinNotify: min, Act: w.act, HeartbeatURL: w.heartbeat,
		State: watch.LoadState(path), Log: stderr,
	}, nil
}

func runWatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "gcp" && args[0] != "aws") {
		fmt.Fprintln(stderr, "usage: billfuse watch gcp|aws [flags]   (-h for flags)")
		return 64
	}
	cloud := args[0]
	fs := flag.NewFlagSet("watch "+cloud, flag.ContinueOnError)
	fs.SetOutput(stderr)
	defDelay := 4 * time.Minute
	if cloud == "aws" {
		defDelay = 2 * time.Minute
	}
	wf := commonWatchFlags(fs, defDelay)

	// cloud-specific
	var projects, bas, regions, deny multi
	token := fs.String("token", "", "GCP: OAuth access token (default: gcloud / metadata server; refreshed every 30 min)")
	quota := fs.String("quota-project", "", "GCP: quota project for user credentials")
	profile := fs.String("profile", os.Getenv("AWS_PROFILE"), "AWS: CLI profile (credentials refreshed every 10 min)")
	if cloud == "gcp" {
		fs.Var(&projects, "project", "GCP project(s) to watch")
		fs.Var(&bas, "billing-account", "watch every billed project on these billing accounts (default: all you can see)")
	} else {
		fs.Var(&regions, "regions", "AWS regions to watch (default: all Bedrock regions)")
		fs.Var(&deny, "act-aws-deny", "kill-switch targets: role:NAME,user:NAME (Deny bedrock:* is attached on CRITICAL with --act)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 64
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if wf.testAlert {
		ns := wf.notifiers()
		if len(ns) == 0 {
			fmt.Fprintln(stderr, "no channels configured (--slack / --telegram-token+--telegram-chat / --webhook / --ntfy)")
			return 64
		}
		code := 0
		for _, n := range ns {
			err := n.Send(ctx, watch.Message{Severity: sev.Info, Title: "test alert - this channel works", Body: "sent by billfuse watch " + cloud + " --test-alert", Time: time.Now()})
			if err != nil {
				fmt.Fprintf(stderr, "%-9s FAILED: %v\n", n.Name(), err)
				code = 1
			} else {
				fmt.Fprintf(stderr, "%-9s ok\n", n.Name())
			}
		}
		return code
	}

	pricing, err := watch.LoadPricing(wf.prices)
	if err != nil {
		fmt.Fprintln(stderr, "prices:", err)
		return 64
	}

	var col watch.Collector
	var actor watch.Actor
	var refresh func() error

	switch cloud {
	case "gcp":
		tok, src, err := resolveToken(ctx, *token)
		if err != nil {
			fmt.Fprintln(stderr, "auth:", err)
			return 1
		}
		c := &gcp.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Token: tok, E: endpointsFromEnv(), QuotaProj: *quota}
		if len(projects) == 0 && len(bas) == 0 {
			accts, err := c.ListBillingAccounts(ctx)
			if err != nil {
				fmt.Fprintln(stderr, "cannot list billing accounts; pass --project:", err)
				return 1
			}
			for _, a := range accts {
				if a.Open {
					bas = append(bas, strings.TrimPrefix(a.Name, "billingAccounts/"))
				}
			}
		}
		col = &watch.GCPCollector{C: c, Projects: projects, BillingAccounts: bas, Pricing: pricing}
		actor = watch.GCPActor{C: c}
		last := time.Now()
		refresh = func() error {
			if *token != "" || time.Since(last) < 30*time.Minute {
				return nil
			}
			t, _, err := resolveToken(ctx, "")
			if err == nil {
				c.Token, last = t, time.Now()
			}
			return err
		}
		fmt.Fprintf(stderr, "billfuse %s · watch gcp · auth via %s · projects %v billing accounts %v\n", version, src, []string(projects), []string(bas))
	case "aws":
		creds, src, err := resolveAWSCreds(ctx, *profile)
		if err != nil {
			fmt.Fprintln(stderr, "auth:", err)
			return 1
		}
		ep := awsc.Endpoint(awsc.DefaultEndpoint)
		if v := os.Getenv("BILLFUSE_AWS_ENDPOINT"); v != "" {
			ep = func(service, region string) string { return v + "/" + service + "/" + region }
		}
		c := &awsc.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Creds: creds, Endpoint: ep}
		id, err := c.CallerIdentity(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "sts:", err)
			return 1
		}
		if len(regions) == 0 {
			regions = awsc.BedrockRegions
		}
		col = &watch.AWSCollector{C: c, Account: id.Account, Regions: regions, Pricing: pricing}
		actor = watch.AWSActor{C: c, Targets: deny}
		last := time.Now()
		refresh = func() error {
			if time.Since(last) < 10*time.Minute || os.Getenv("AWS_ACCESS_KEY_ID") != "" {
				return nil
			}
			cr, _, err := resolveAWSCreds(ctx, *profile)
			if err == nil {
				c.Creds, last = cr, time.Now()
			}
			return err
		}
		fmt.Fprintf(stderr, "billfuse %s · watch aws · account %s · auth via %s · %d regions\n", version, id.Account, src, len(regions))
	}

	cfg, err := wf.config(cloud, col, actor, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 64
	}
	mode := "DRY-RUN (kill switch only reports; add --act to enforce)"
	if wf.act {
		mode = "ARMED - kill switch WILL act on CRITICAL"
	}
	var chans []string
	for _, n := range cfg.Notifiers {
		chans = append(chans, n.Name())
	}
	if len(chans) == 0 {
		chans = []string{"terminal only - add --slack/--telegram-*/--ntfy/--webhook"}
	}
	fmt.Fprintf(stderr, "limits: $%g/h · $%g/day · spike %.0fx · rpm %s · every %s over %s (delay %s)\n",
		wf.maxHourly, wf.maxDaily, wf.spike, orOff(wf.maxRPM), wf.interval, wf.window, wf.delay)
	fmt.Fprintf(stderr, "mode: %s · alerts -> %s · heartbeat %s\n", mode, strings.Join(chans, ", "), orNone(wf.heartbeat))
	fmt.Fprintln(stderr, "costs are ESTIMATES from per-minute usage metrics x list prices, not your bill")

	exit := 0
	for {
		if err := refresh(); err != nil {
			fmt.Fprintln(stderr, "credential refresh failed:", err)
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute+wf.interval)
		res, err := watch.Cycle(cctx, cfg)
		cancel()
		_ = watch.Heartbeat(ctx, wf.heartbeat, err != nil)
		if err != nil {
			fmt.Fprintln(stderr, time.Now().Format("15:04:05"), "cycle error:", err)
			exit = 1
		} else {
			if wf.asJSON {
				json.NewEncoder(stdout).Encode(res)
			} else {
				fmt.Fprintln(stdout, watch.StatusLine(res))
				for _, a := range res.Actions {
					fmt.Fprintln(stdout, "  KILL SWITCH:", strings.ReplaceAll(a, "\n", "\n  "))
				}
				for _, w := range res.Warnings {
					fmt.Fprintln(stderr, "  warn:", w)
				}
			}
			exit = 0
			for _, a := range res.Alerts {
				if a.Severity == sev.Critical && !a.Resolved {
					exit = 2
				}
			}
		}
		if wf.once {
			return exit
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "stopped")
			return 0
		case <-time.After(wf.interval):
		}
	}
}

func orOff(f float64) string {
	if f == 0 {
		return "off"
	}
	return fmt.Sprintf("%.0f/min", f)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return "on"
}
