package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jhelbling/billfuse/internal/gcpfake"
)

func TestCLIText(t *testing.T) {
	srv := gcpfake.New(t)
	defer srv.Close()
	t.Setenv("BILLFUSE_GCP_ENDPOINT", srv.URL)
	var out, errb bytes.Buffer
	code := runAuditGCP([]string{"--token", "test"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit code %d, want 2 (critical findings); stderr=%s", code, errb.String())
	}
	for _, s := range []string{"PROJECT_INVISIBLE", "xx-miner-4821", "KEY_UNRESTRICTED_AI", "Nothing was changed"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("output missing %q", s)
		}
	}
	t.Log("\n" + out.String())
}

func TestCLIJSONAndFailOnNone(t *testing.T) {
	srv := gcpfake.New(t)
	defer srv.Close()
	t.Setenv("BILLFUSE_GCP_ENDPOINT", srv.URL)
	var out, errb bytes.Buffer
	if code := runAuditGCP([]string{"--token", "test", "--json", "--fail-on", "none"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var r map[string]any
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r["findings"].([]any)) < 5 {
		t.Error("too few findings in JSON")
	}
}
