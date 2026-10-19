package aws

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test vector from the AWS SigV4 documentation ("Examples of the complete
// Signature Version 4 signing process": IAM ListUsers, 2015-08-30).
func TestSignAWSDocVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	Sign(req, nil, Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam", now)
	got := req.Header.Get("Authorization")
	want := "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("signature mismatch:\n got %s\nwant ...%s", got, want)
	}
	if !strings.Contains(got, "SignedHeaders=content-type;host;x-amz-date,") {
		t.Errorf("signed headers: %s", got)
	}
}
