package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jhelbling/billfuse/internal/awsfake"
	"github.com/jhelbling/billfuse/internal/gcpfake"
)

type demoLog struct{ w io.Writer }

func (d demoLog) Errorf(f string, a ...any) { fmt.Fprintf(d.w, "demo: "+f+"\n", a...) }

// runDemo runs every command against built-in fake GCP and AWS accounts seeded
// with real-world incident patterns - no cloud credentials needed.
func runDemo(stdout, stderr io.Writer) int {
	g := gcpfake.New(demoLog{stderr})
	defer g.Close()
	a := awsfake.New(demoLog{stderr})
	defer a.Close()

	set := func(k, v string) { os.Setenv(k, v) }
	set("BILLFUSE_GCP_ENDPOINT", g.URL)
	set("BILLFUSE_AWS_ENDPOINT", a.URL)
	set("AWS_PROFILE", "")
	set("AWS_ACCESS_KEY_ID", "AKIDTEST")
	set("AWS_SECRET_ACCESS_KEY", "demo")
	tmp, _ := os.MkdirTemp("", "billfuse-demo")
	defer os.RemoveAll(tmp)

	banner := func(s string) {
		fmt.Fprintf(stdout, "\n\033[1m════ %s ════\033[0m\n", s)
	}
	fmt.Fprintln(stdout, "billfuse demo - fake GCP + AWS accounts seeded with patterns from real incidents.")
	fmt.Fprintln(stdout, "Nothing here touches your cloud.")

	banner("$ billfuse audit gcp")
	runAuditGCP([]string{"--token", "test", "--fail-on", "none", "--no-usage"}, stdout, stdout)

	banner("$ billfuse audit aws --expected-regions us-east-1")
	runAuditAWS([]string{"--regions", "us-east-1,ap-south-2", "--expected-regions", "us-east-1", "--fail-on", "none"}, stdout, stdout)

	banner("$ billfuse watch aws --once --max-hourly 20 --act-aws-deny role:gitlab-runner   (dry-run)")
	runWatch([]string{"aws", "--once", "--regions", "us-east-1,ap-south-2", "--max-hourly", "20",
		"--act-aws-deny", "role:gitlab-runner", "--state", tmp + "/state.json"}, stdout, stdout)

	fmt.Fprintln(stdout, "\nTry it on your own account (read-only):  billfuse audit gcp   |   billfuse audit aws --profile <p>")
	return 0
}
