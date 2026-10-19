# billfuse

Spend guard for AI APIs on Google Cloud and AWS.

Budget alerts are based on billing data, which can be hours behind. billfuse reads usage metrics instead (Cloud Monitoring, CloudWatch), which show up within a few minutes, and can cut off the API or role that is burning money.

Three commands:

- `billfuse audit gcp` / `billfuse audit aws`: read-only scan for the setups that usually end in a surprise bill.
- `billfuse watch gcp|aws`: polls usage every minute, estimates $/hour, alerts, and optionally trips a kill switch.
- `billfuse demo`: runs all of the above against built-in fake accounts. No credentials needed.

Single static binary, no dependencies outside the Go standard library.

## Install

Download a binary from [Releases](../../releases), or build from source (Go 1.22+):

```
go install github.com/jhelbling/billfuse/cmd/billfuse@latest
```

On macOS, a downloaded binary needs `xattr -c ./billfuse` before the first run.

## audit gcp

```
gcloud auth login
billfuse audit gcp
billfuse audit gcp --billing-account 0123AB-CDEF45-678901
billfuse audit gcp --project my-app --json
```

What it looks at:

- every project billed to your billing accounts, including projects you can't read (a known way to end up paying for someone else's mining)
- every API key: which APIs it can call, whether it has an application restriction, how old it is, and how many requests it served in the last 30 days
- paid APIs that accept a bare API key (Gemini, Vertex, Translate, Vision, Maps, ...)

| Code | Severity | Meaning |
|---|---|---|
| `PROJECT_INVISIBLE` | critical | billed to your account, but you can't read it |
| `KEY_UNRESTRICTED_AI` | critical | key without API restrictions, Gemini or Vertex enabled |
| `KEY_UNRESTRICTED_BILLABLE` | high | key without API restrictions, another paid key-callable API enabled |
| `PROJECT_FOREIGN_ORG` | high | billed project in a different org than the rest |
| `KEY_AI_ACCESS` | high / medium | key allowed to call Gemini or Vertex (medium if app-restricted) |
| `PROJECT_RECENT` | medium | billed project created in the last 30 days |
| `KEY_UNRESTRICTED` | medium | key without API restrictions |
| `KEY_BILLABLE_ACCESS` | medium | key for a paid API without app restriction |
| `BA_DORMANT_OPEN` | low | open billing account with no projects |
| `PROJECT_NO_ORG` | low | project outside any organization |

An empty application restriction (for example `androidKeyRestrictions: {}`) is treated as no restriction. The console shows such keys as restricted.

Roles needed (all read-only): `billing.viewer`, `browser`, `serviceusage.serviceUsageViewer`, `serviceusage.apiKeysViewer`, `monitoring.viewer`.

## audit aws

```
aws sso login --profile prod
billfuse audit aws --profile prod
billfuse audit aws --profile prod --expected-regions us-east-1,eu-central-1
```

- who can call `bedrock:InvokeModel*`: users and roles, through groups, inline and managed policies, permission boundaries, explicit denies, `NotAction`
- long-lived access keys that can call Bedrock, with age and last use
- roles assumable from outside the account or by `*`
- EC2/ECS/Lambda/CodeBuild roles with `AdministratorAccess` (any job on that box can call Bedrock)
- Bedrock invocations and tokens per model in every region over the last 30 days, and whether invocation logging is on

| Code | Severity | Meaning |
|---|---|---|
| `ROOT_ACCESS_KEY` | critical | root user has access keys |
| `KEY_BEDROCK_DORMANT` | critical | access key can call Bedrock, unused for 90+ days |
| `ROLE_BEDROCK_PUBLIC_TRUST` | critical | role can call Bedrock, trust policy allows `*` |
| `KEY_BEDROCK` | high | access key in use that can call Bedrock |
| `ROLE_BEDROCK_EXTERNAL_TRUST` | high | another account can assume it without `sts:ExternalId` |
| `BEDROCK_UNEXPECTED_REGION` | high | Bedrock used outside `--expected-regions` |
| `ROLE_WORKLOAD_ADMIN` | medium | compute role with AdministratorAccess or PowerUserAccess |
| `BEDROCK_MANY_REGIONS` | medium | Bedrock used in 3+ regions |
| `BEDROCK_LOGGING_OFF` | low | Bedrock used, invocation logging off |
| `KEY_DORMANT` | low | access key unused for 90+ days |
| `ROLE_ORG_MANAGEMENT_TRUST` | info | assumable by the org management account (expected) |

Credentials come from the environment or `aws configure export-credentials`, so SSO profiles work. Requests are signed with SigV4 and the client only allows `List*`, `Get*` and `Describe*` actions. Permissions: `SecurityAudit` + `CloudWatchReadOnlyAccess`, or `ReadOnlyAccess`.

The policy evaluation is a heuristic. SCPs, resource policies and condition contents are not evaluated.

## watch

```
billfuse watch gcp --max-hourly 20 --max-daily 200 --ntfy https://ntfy.sh/<topic>
billfuse watch aws --profile prod --expected-regions us-east-1 \
    --slack "$SLACK_WEBHOOK" --act-aws-deny role:gitlab-runner
billfuse watch aws --test-alert --slack "$SLACK_WEBHOOK"
```

Sources:

| | Metric | Delay |
|---|---|---|
| Gemini API | `serviceruntime.googleapis.com/api/request_count` per key and method | 3-4 min |
| Vertex AI | `aiplatform.googleapis.com/publisher/online_serving/token_count` per model | a few min |
| Bedrock | `AWS/Bedrock` Invocations / InputTokenCount / OutputTokenCount per model and region | 1-2 min |

Cost is tokens x list price. Prices can be overridden with `--prices file.json`. Unknown models are priced high on purpose. The Gemini API has no token metric, so it is priced per successful inference request ($0.01 default). Failed requests and free calls (ListModels, CountTokens) are not counted as spend, but failed requests are reported since they often mean someone is trying a stolen key. All amounts are estimates, not your bill.

Rules, per GCP project or AWS account:

| Rule | Severity |
|---|---|
| $/hour over `--max-hourly` (default 25) | critical, kill switch |
| $ since 00:00 UTC over `--max-daily` (default 250) | critical, kill switch |
| requests/min over `--max-rpm` | high |
| $/hour over `--spike` x learned baseline | high |
| traffic in a region outside `--expected-regions` | high |
| first traffic from a new model, region or key | medium |

The baseline only learns from cycles without a spike. A firing alert repeats at most every `--cooldown` (30m) and sends a resolved message when it clears.

The kill switch is a dry run unless you pass `--act`. It runs at most once per scope per day.

- GCP: disables the AI APIs that had traffic on the project. Undo with `gcloud services enable`.
- AWS: attaches an inline `billfuse-deny-bedrock` policy to the roles/users given in `--act-aws-deny`. CloudWatch doesn't say who is calling, so you choose the targets.

Alert channels: Slack webhook, Telegram bot, ntfy, generic JSON webhook. `--heartbeat <url>` pings a dead man's switch (healthchecks.io etc.) after every cycle.

For cron or a scheduled job use `--once` with a persistent `--state` file. Exit code 2 means a critical alert fired.

Extra permissions for `--act`: `serviceusage.services.disable` on GCP, `iam:PutRolePolicy` / `iam:PutUserPolicy` on AWS.

## Development

```
go test ./...
go run ./cmd/billfuse demo
```

Tests run against in-process fakes of the GCP and AWS APIs (`internal/gcpfake`, `internal/awsfake`).

## License

MIT
