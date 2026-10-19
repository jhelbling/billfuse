package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jhelbling/billfuse/internal/sev"
)

type Message struct {
	Severity sev.Severity `json:"severity"`
	Title    string       `json:"title"`
	Body     string       `json:"body"`
	Time     time.Time    `json:"time"`
}

func (m Message) Text() string {
	t := fmt.Sprintf("[billfuse %s] %s", m.Severity, m.Title)
	if m.Body != "" {
		t += "\n" + m.Body
	}
	return t
}

type Notifier interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

var httpc = &http.Client{Timeout: 10 * time.Second}

func postJSON(ctx context.Context, u string, v any) error {
	b, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Slack incoming webhook.
type Slack struct{ URL string }

func (Slack) Name() string { return "slack" }
func (s Slack) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, s.URL, map[string]string{"text": m.Text()})
}

// Telegram bot.
type Telegram struct {
	Token, ChatID string
	Base          string // tests
}

func (Telegram) Name() string { return "telegram" }
func (t Telegram) Send(ctx context.Context, m Message) error {
	base := t.Base
	if base == "" {
		base = "https://api.telegram.org"
	}
	return postJSON(ctx, base+"/bot"+t.Token+"/sendMessage", map[string]any{"chat_id": t.ChatID, "text": m.Text(), "disable_web_page_preview": true})
}

// Webhook posts the raw Message JSON (for PagerDuty/Opsgenie bridges, n8n, Zapier, ...).
type Webhook struct{ URL string }

func (Webhook) Name() string                                { return "webhook" }
func (w Webhook) Send(ctx context.Context, m Message) error { return postJSON(ctx, w.URL, m) }

// Ntfy pushes to an ntfy.sh topic - the quickest way to get a phone push.
type Ntfy struct{ URL string } // e.g. https://ntfy.sh/my-secret-topic

func (Ntfy) Name() string { return "ntfy" }
func (n Ntfy) Send(ctx context.Context, m Message) error {
	req, err := http.NewRequestWithContext(ctx, "POST", n.URL, strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", "billfuse "+m.Severity.String()+": "+m.Title)
	prio := map[sev.Severity]string{sev.Critical: "urgent", sev.High: "high"}[m.Severity]
	if prio != "" {
		req.Header.Set("Priority", prio)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Heartbeat pings a dead-man's-switch URL (healthchecks.io, Better Stack, Cronitor...)
// after every successful cycle, so you also hear about it when billfuse itself dies.
func Heartbeat(ctx context.Context, u string, failed bool) error {
	if u == "" {
		return nil
	}
	if failed {
		if pu, err := url.Parse(u); err == nil && strings.Contains(pu.Host, "hc-ping") {
			u = strings.TrimRight(u, "/") + "/fail"
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
