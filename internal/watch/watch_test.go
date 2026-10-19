package watch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awsc "github.com/jhelbling/billfuse/internal/aws"
	"github.com/jhelbling/billfuse/internal/awsfake"
	"github.com/jhelbling/billfuse/internal/sev"
)

type fakeCollector struct {
	recent, today []Sample
}

func (f *fakeCollector) Cloud() string { return "aws" }
func (f *fakeCollector) Collect(_ context.Context, start, end time.Time) ([]Sample, []string, error) {
	if end.Sub(start) > time.Hour {
		return f.today, nil, nil
	}
	return f.recent, nil, nil
}

type memNotifier struct {
	mu   sync.Mutex
	msgs []Message
}

func (m *memNotifier) Name() string { return "mem" }
func (m *memNotifier) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}

type memActor struct{ calls []bool }

func (a *memActor) Act(_ context.Context, scope string, _ []Sample, dry bool) (string, error) {
	a.calls = append(a.calls, dry)
	if dry {
		return "[dry-run] would deny " + scope, nil
	}
	return "DONE deny " + scope, nil
}

func smp(region, model string, req, in, out float64) Sample {
	p := DefaultPricing()
	c, known := p.TokenCost(model, in, out)
	return Sample{Cloud: "aws", Scope: "111", Region: region, Service: "bedrock", Model: model, Requests: req, InTok: in, OutTok: out, Cost: c, PriceKnown: known}
}

func TestPricing(t *testing.T) {
	p := DefaultPricing()
	c, ok := p.TokenCost("anthropic.claude-sonnet-4-5-20250929-v1:0", 1e6, 1e6)
	if !ok || c != 18 {
		t.Errorf("sonnet 1M/1M = %v %v, want 18", c, ok)
	}
	c, ok = p.TokenCost("us.anthropic.claude-opus-4-5", 1e6, 0)
	if !ok || c != 5 {
		t.Errorf("opus 4.5 input = %v", c)
	}
	if _, ok := p.TokenCost("mystery.model", 1, 1); ok {
		t.Error("unknown model should not be known")
	}
}

func TestCycleSpikeThresholdActAndResolve(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return now }
	defer func() { nowFn = time.Now }()

	fc := &fakeCollector{}
	n := &memNotifier{}
	act := &memActor{}
	st := LoadState(filepath.Join(t.TempDir(), "state.json"))
	cfg := &Config{Collector: fc, Notifiers: []Notifier{n}, Actor: act, State: st, MinNotify: sev.Medium,
		Limits: Limits{MaxHourly: 50, MaxDaily: 500, SpikeFactor: 5, SpikeFloor: 2, Warmup: 3, Expected: map[string]bool{"us-east-1": true}}}

	// Warm-up: steady haiku usage in us-east-1 (~$0.30/h).
	fc.recent = []Sample{smp("us-east-1", "anthropic.claude-haiku-4-5", 100, 40000, 2000)}
	fc.today = fc.recent
	for i := 0; i < 4; i++ {
		if _, err := Cycle(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	if len(n.msgs) != 0 {
		t.Fatalf("warm-up should be silent, got %v", n.msgs)
	}

	// Attack: opus in ap-south-2, ~$900/h.
	fc.recent = append(fc.recent, smp("ap-south-2", "anthropic.claude-opus-4-1", 3000, 9e6, 900000))
	fc.today = fc.recent
	res, err := Cycle(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	titles := []string{}
	for _, m := range n.msgs {
		titles = append(titles, m.Severity.String()+" "+m.Title)
	}
	all := strings.Join(titles, "\n")
	for _, want := range []string{"CRITICAL aws 111 burning", "HIGH aws 111 spend spiked", "HIGH aws 111: AI usage in UNEXPECTED region ap-south-2", "MEDIUM aws 111: first traffic from new model anthropic.claude-opus-4-1"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing alert %q in:\n%s", want, all)
		}
	}
	if len(act.calls) != 1 || !act.calls[0] {
		t.Errorf("kill switch should run once in dry-run, calls=%v", act.calls)
	}
	if len(res.Actions) != 1 || !strings.Contains(res.Actions[0], "[dry-run]") {
		t.Errorf("actions = %v", res.Actions)
	}

	// Next minutes, still burning: cooldown suppresses repeats and the dry-run plan isn't repeated.
	before := len(n.msgs)
	for i := 0; i < 3; i++ {
		now = now.Add(time.Minute)
		if _, err := Cycle(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.msgs) != before {
		t.Errorf("still-firing alerts should be throttled for the cooldown, got %d extra", len(n.msgs)-before)
	}
	if len(act.calls) != 1 {
		t.Errorf("dry-run plan should be produced once per day, calls=%v", act.calls)
	}
	// After the cooldown the critical alert repeats.
	now = now.Add(31 * time.Minute)
	Cycle(context.Background(), cfg)
	if len(n.msgs) == before {
		t.Error("alert should repeat after cooldown")
	}

	// Attack stops -> resolved messages for alerts that were notified.
	fc.recent = []Sample{smp("us-east-1", "anthropic.claude-haiku-4-5", 100, 40000, 2000)}
	before = len(n.msgs)
	now = now.Add(time.Minute)
	if _, err := Cycle(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	resolved := 0
	for _, m := range n.msgs[before:] {
		if strings.Contains(m.Title, "resolved") {
			resolved++
		}
	}
	if resolved < 2 {
		t.Errorf("expected resolved messages for hourly+spike, got %d", resolved)
	}

	// State persisted and reloadable.
	st2 := LoadState(st.path)
	if st2.Cycles != st.Cycles || len(st2.Seen) == 0 {
		t.Errorf("state not persisted: %+v", st2)
	}
}

func TestActForReal(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return now }
	defer func() { nowFn = time.Now }()
	fc := &fakeCollector{recent: []Sample{smp("us-east-1", "anthropic.claude-opus-4-1", 3000, 9e6, 900000)}}
	fc.today = fc.recent
	act := &memActor{}
	cfg := &Config{Collector: fc, Actor: act, Act: true, Limits: Limits{MaxHourly: 10}}
	for i := 0; i < 3; i++ {
		Cycle(context.Background(), cfg)
		now = now.Add(time.Minute)
	}
	if len(act.calls) != 1 || act.calls[0] {
		t.Errorf("real kill switch should run exactly once per day, calls=%v", act.calls)
	}
}

func TestNotifiers(t *testing.T) {
	var got []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+r.Header.Get("Title")+" "+string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	m := Message{Severity: sev.Critical, Title: "aws 111 burning ~$900/h", Body: "detail"}
	ctx := context.Background()
	for _, n := range []Notifier{Slack{srv.URL + "/slack"}, Telegram{Token: "T", ChatID: "42", Base: srv.URL}, Webhook{srv.URL + "/hook"}, Ntfy{srv.URL + "/topic"}} {
		if err := n.Send(ctx, m); err != nil {
			t.Errorf("%s: %v", n.Name(), err)
		}
	}
	if err := Heartbeat(ctx, srv.URL+"/hb", false); err != nil {
		t.Error(err)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"/slack", `"text":"[billfuse CRITICAL]`, "/botT/sendMessage", `"chat_id":"42"`, "/hook", `"severity":"CRITICAL"`, "/topic billfuse CRITICAL", "/hb"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
}

func TestAWSCollectorAgainstFake(t *testing.T) {
	srv := awsfake.New(t)
	defer srv.Close()
	c := &awsc.Client{HTTP: srv.Client(), Creds: awsc.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "s"}, Endpoint: awsfake.Endpoint(srv.URL)}
	col := &AWSCollector{C: c, Account: "111111111111", Regions: []string{"us-east-1", "ap-south-2", "me-central-1"}, Pricing: DefaultPricing()}
	end := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	s, warns, err := col.Collect(context.Background(), end.Add(-10*time.Minute), end)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	b, _ := json.Marshal(s)
	if len(s) != 2 || !strings.Contains(string(b), "anthropic.claude-opus") || !strings.Contains(string(b), `"region":"ap-south-2"`) {
		t.Errorf("samples = %s", b)
	}
	if !col.dead["me-central-1"] {
		t.Error("disabled region should be remembered as dead")
	}
}

func TestAWSActorAgainstFake(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, string(b))
		w.Write([]byte(`<PutRolePolicyResponse/>`))
	}))
	defer srv.Close()
	c := &awsc.Client{HTTP: srv.Client(), Creds: awsc.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "s"}, Endpoint: awsfake.Endpoint(srv.URL)}
	a := AWSActor{C: c, Targets: []string{"role:gitlab-runner", "user:ci-bot", "bogus"}}
	out, err := a.Act(context.Background(), "111", nil, true)
	if err != nil || len(calls) != 0 || !strings.Contains(out, "[dry-run]") {
		t.Fatalf("dry-run must not call AWS: out=%q calls=%v err=%v", out, calls, err)
	}
	out, err = a.Act(context.Background(), "111", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "Action=PutRolePolicy") || !strings.Contains(calls[1], "Action=PutUserPolicy") || !strings.Contains(out, "skipped bad target bogus") {
		t.Errorf("calls=%v out=%s", calls, out)
	}
}
