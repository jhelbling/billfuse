package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jhelbling/billfuse/internal/awsfake"
)

func TestWatchAWSOnce(t *testing.T) {
	srv := awsfake.New(t)
	defer srv.Close()
	var hooks []string
	var mu sync.Mutex
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		hooks = append(hooks, r.URL.Path+" "+string(b))
		mu.Unlock()
	}))
	defer hook.Close()
	t.Setenv("BILLFUSE_AWS_ENDPOINT", srv.URL)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	var out, errb bytes.Buffer
	state := filepath.Join(t.TempDir(), "s.json")
	code := runWatch([]string{"aws", "--once", "--regions", "us-east-1,ap-south-2", "--state", state,
		"--max-hourly", "20", "--webhook", hook.URL + "/hook", "--heartbeat", hook.URL + "/hb",
		"--act-aws-deny", "role:gitlab-runner"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (critical)\nstdout:%s\nstderr:%s", code, out.String(), errb.String())
	}
	all := out.String() + errb.String()
	for _, s := range []string{"DRY-RUN", "KILL SWITCH: [dry-run] would attach Deny bedrock:* to role gitlab-runner", "total ~$"} {
		if !strings.Contains(all, s) {
			t.Errorf("missing %q in\n%s", s, all)
		}
	}
	joined := strings.Join(hooks, "\n")
	if !strings.Contains(joined, "/hook") || !strings.Contains(joined, "CRITICAL") || !strings.Contains(joined, "/hb") {
		t.Errorf("webhook/heartbeat not called: %s", joined)
	}
	t.Log("\n" + all)
}

func TestWatchTestAlert(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hook.Close()
	var out, errb bytes.Buffer
	if code := runWatch([]string{"gcp", "--test-alert", "--webhook", hook.URL, "--slack", hook.URL}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "webhook   ok") || !strings.Contains(errb.String(), "slack") {
		t.Errorf("stderr: %s", errb.String())
	}
}
