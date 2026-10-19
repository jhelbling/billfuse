// Package awsfake is a fake AWS (IAM/STS/CloudWatch/Bedrock) used by tests.
// Requests arrive at /<service>/<region>/... (see Endpoint).
package awsfake

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func enc(doc string) string { return url.QueryEscape(doc) }

const (
	adminPolicy   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	bedrockFull   = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["bedrock:*"],"Resource":"*"}}`
	s3Only        = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	invokeCond    = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"bedrock:InvokeModel*","Resource":"arn:aws:bedrock:*::foundation-model/*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`
	denyBedrock   = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"bedrock:*","Resource":"*"}]}`
	trustExternal = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`
	trustLambda   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	trustMgmt     = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`
	trustEC2      = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	trustPublic   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
)

func Endpoint(base string) func(service, region string) string {
	return func(service, region string) string { return base + "/" + service + "/" + region }
}

// T is the subset of testing.TB the fake needs (also satisfied by the demo logger).
type T interface {
	Errorf(format string, args ...any)
}

func New(t T) *httptest.Server {
	authz := fmt.Sprintf(`<GetAccountAuthorizationDetailsResponse><GetAccountAuthorizationDetailsResult>
<IsTruncated>false</IsTruncated>
<UserDetailList>
 <member><UserName>ci-bot</UserName><Arn>arn:aws:iam::111111111111:user/ci-bot</Arn>
  <AttachedManagedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedManagedPolicies>
 </member>
 <member><UserName>ml-app</UserName><Arn>arn:aws:iam::111111111111:user/ml-app</Arn>
  <GroupList><member>ml</member></GroupList>
 </member>
 <member><UserName>reports</UserName><Arn>arn:aws:iam::111111111111:user/reports</Arn>
  <UserPolicyList><member><PolicyName>s3read</PolicyName><PolicyDocument>%s</PolicyDocument></member></UserPolicyList>
 </member>
 <member><UserName>office</UserName><Arn>arn:aws:iam::111111111111:user/office</Arn>
  <UserPolicyList><member><PolicyName>invoke-from-office</PolicyName><PolicyDocument>%s</PolicyDocument></member></UserPolicyList>
 </member>
 <member><UserName>blocked</UserName><Arn>arn:aws:iam::111111111111:user/blocked</Arn>
  <AttachedManagedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedManagedPolicies>
  <UserPolicyList><member><PolicyName>no-bedrock</PolicyName><PolicyDocument>%s</PolicyDocument></member></UserPolicyList>
 </member>
</UserDetailList>
<GroupDetailList>
 <member><GroupName>ml</GroupName>
  <AttachedManagedPolicies><member><PolicyName>AmazonBedrockFullAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AmazonBedrockFullAccess</PolicyArn></member></AttachedManagedPolicies>
 </member>
</GroupDetailList>
<RoleDetailList>
 <member><RoleName>vendor-analytics</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/vendor-analytics</Arn>
  <AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument>
  <AttachedManagedPolicies><member><PolicyName>AmazonBedrockFullAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AmazonBedrockFullAccess</PolicyArn></member></AttachedManagedPolicies>
 </member>
 <member><RoleName>open-door</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/open-door</Arn>
  <AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument>
  <RolePolicyList><member><PolicyName>br</PolicyName><PolicyDocument>%s</PolicyDocument></member></RolePolicyList>
 </member>
 <member><RoleName>summarizer-lambda</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/summarizer-lambda</Arn>
  <AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument>
  <AttachedManagedPolicies><member><PolicyName>AmazonBedrockFullAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AmazonBedrockFullAccess</PolicyArn></member></AttachedManagedPolicies>
  <RoleLastUsed><LastUsedDate>2026-10-18T10:00:00Z</LastUsedDate></RoleLastUsed>
 </member>
 <member><RoleName>OrganizationAccountAccessRole</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/OrganizationAccountAccessRole</Arn>
  <AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument>
  <AttachedManagedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedManagedPolicies>
 </member>
 <member><RoleName>gitlab-runner</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/gitlab-runner</Arn>
  <AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument>
  <AttachedManagedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedManagedPolicies>
  <RoleLastUsed><LastUsedDate>2026-10-19T08:00:00Z</LastUsedDate></RoleLastUsed>
 </member>
</RoleDetailList>
<Policies>
 <member><PolicyName>AdministratorAccess</PolicyName><Arn>arn:aws:iam::aws:policy/AdministratorAccess</Arn>
  <PolicyVersionList><member><Document>%s</Document><IsDefaultVersion>true</IsDefaultVersion></member></PolicyVersionList></member>
 <member><PolicyName>AmazonBedrockFullAccess</PolicyName><Arn>arn:aws:iam::aws:policy/AmazonBedrockFullAccess</Arn>
  <PolicyVersionList><member><Document>%s</Document><IsDefaultVersion>true</IsDefaultVersion></member></PolicyVersionList></member>
</Policies>
</GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>`,
		enc(s3Only), enc(invokeCond), enc(denyBedrock), enc(trustExternal), enc(trustPublic), enc(bedrockFull), enc(trustLambda), enc(trustMgmt), enc(trustEC2), enc(adminPolicy), enc(bedrockFull))

	keys := map[string]string{
		"ci-bot":  `<member><UserName>ci-bot</UserName><AccessKeyId>AKIAOLDCIBOT0001</AccessKeyId><Status>Active</Status><CreateDate>2019-03-01T00:00:00Z</CreateDate></member>`,
		"ml-app":  `<member><UserName>ml-app</UserName><AccessKeyId>AKIAMLAPP0000002</AccessKeyId><Status>Active</Status><CreateDate>2025-01-01T00:00:00Z</CreateDate></member>`,
		"reports": `<member><UserName>reports</UserName><AccessKeyId>AKIAREPORTS00003</AccessKeyId><Status>Active</Status><CreateDate>2024-01-01T00:00:00Z</CreateDate></member>`,
		"office":  `<member><UserName>office</UserName><AccessKeyId>AKIAOFFICE000004</AccessKeyId><Status>Active</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member>`,
		"blocked": `<member><UserName>blocked</UserName><AccessKeyId>AKIABLOCKED00005</AccessKeyId><Status>Inactive</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member>`,
	}
	lastUsed := map[string]string{
		"AKIAOLDCIBOT0001": `<LastUsedDate>2025-11-02T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region>`,
		"AKIAMLAPP0000002": `<LastUsedDate>2026-10-18T00:00:00Z</LastUsedDate><ServiceName>bedrock</ServiceName><Region>us-east-1</Region>`,
		"AKIAREPORTS00003": `<ServiceName>N/A</ServiceName><Region>N/A</Region>`,
		"AKIAOFFICE000004": `<LastUsedDate>2026-10-17T00:00:00Z</LastUsedDate><ServiceName>bedrock</ServiceName><Region>eu-central-1</Region>`,
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
			w.WriteHeader(403)
			fmt.Fprint(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>bad sig</Message></Error></ErrorResponse>`)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
		service, region := parts[0], parts[1]
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		action := form.Get("Action")
		if r.Method != "GET" && r.Header.Get("X-Amz-Target") == "" && !(strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "Describe")) {
			t.Errorf("non-read-only call: %s %s", r.Method, action)
		}
		x := func(s string) { w.Header().Set("Content-Type", "text/xml"); fmt.Fprint(w, s) }

		switch {
		case service == "organizations":
			if !strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeOrganization") {
				t.Errorf("unexpected organizations call %s", r.Header.Get("X-Amz-Target"))
			}
			fmt.Fprint(w, `{"Organization":{"Id":"o-abc","MasterAccountId":"222222222222"}}`)
		case service == "sts" && action == "GetCallerIdentity":
			x(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::111111111111:user/alice</Arn><Account>111111111111</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case service == "iam" && action == "GetAccountSummary":
			x(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>Users</key><value>5</value></entry><entry><key>AccountAccessKeysPresent</key><value>1</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`)
		case service == "iam" && action == "GetAccountAuthorizationDetails":
			x(authz)
		case service == "iam" && action == "ListAccessKeys":
			x(`<ListAccessKeysResponse><ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata>` + keys[form.Get("UserName")] + `</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`)
		case service == "iam" && action == "GetAccessKeyLastUsed":
			x(`<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><AccessKeyLastUsed>` + lastUsed[form.Get("AccessKeyId")] + `</AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
		case service == "monitoring" && action == "ListMetrics":
			switch region {
			case "us-east-1":
				x(`<ListMetricsResponse><ListMetricsResult><Metrics><member><Namespace>AWS/Bedrock</Namespace><MetricName>Invocations</MetricName><Dimensions><member><Name>ModelId</Name><Value>anthropic.claude-haiku</Value></member></Dimensions></member></Metrics></ListMetricsResult></ListMetricsResponse>`)
			case "ap-south-2":
				x(`<ListMetricsResponse><ListMetricsResult><Metrics><member><Namespace>AWS/Bedrock</Namespace><MetricName>Invocations</MetricName><Dimensions><member><Name>ModelId</Name><Value>anthropic.claude-opus</Value></member></Dimensions></member></Metrics></ListMetricsResult></ListMetricsResponse>`)
			case "me-south-1":
				time.Sleep(13 * time.Second)
			case "me-central-1":
				w.WriteHeader(403)
				fmt.Fprint(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>`)
			default:
				x(`<ListMetricsResponse><ListMetricsResult><Metrics/></ListMetricsResult></ListMetricsResponse>`)
			}
		case service == "monitoring" && action == "GetMetricStatistics":
			n := "120"
			if region == "ap-south-2" {
				n = "48000"
			}
			if form.Get("MetricName") != "Invocations" {
				n = "1000000"
			}
			// Short windows (watch) scale with the period so "today" ≥ "last 10 min".
			if per, _ := strconv.Atoi(form.Get("Period")); per > 0 && per != 86400 && per > 600 {
				v, _ := strconv.ParseFloat(n, 64)
				n = strconv.FormatFloat(v*float64(per)/600, 'f', 0, 64)
			}
			x(`<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints><member><Timestamp>2026-10-17T00:00:00Z</Timestamp><Sum>` + n + `</Sum></member></Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>`)
		case service == "bedrock" && strings.HasSuffix(r.URL.Path, "/logging/modelinvocations"):
			if region == "us-east-1" {
				fmt.Fprint(w, `{"loggingConfig":{"cloudWatchConfig":{"logGroupName":"bedrock"}}}`)
			} else {
				fmt.Fprint(w, `{}`)
			}
		default:
			w.WriteHeader(400)
			fmt.Fprintf(w, `<ErrorResponse><Error><Code>Unhandled</Code><Message>%s %s</Message></Error></ErrorResponse>`, service, action)
		}
	}))
}
