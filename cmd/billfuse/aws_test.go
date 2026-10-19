package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jhelbling/billfuse/internal/awsfake"
)

func TestCLIAWS(t *testing.T) {
	srv := awsfake.New(t)
	defer srv.Close()
	t.Setenv("BILLFUSE_AWS_ENDPOINT", srv.URL)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	var out, errb bytes.Buffer
	code := runAuditAWS([]string{"--expected-regions", "us-east-1", "--regions", "us-east-1,ap-south-2,eu-west-1"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d; stderr=%s", code, errb.String())
	}
	for _, s := range []string{"KEY_BEDROCK_DORMANT", "ROOT_ACCESS_KEY", "BEDROCK_UNEXPECTED_REGION", "ap-south-2", "Nothing was changed"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("missing %q", s)
		}
	}
	t.Log("\n" + out.String())
}
