package aws

import (
	"encoding/json"
	"net/url"
	"strings"
)

// InvokeActions are the IAM actions that let a principal run (and pay for) Bedrock inference.
var InvokeActions = []string{
	"bedrock:InvokeModel",
	"bedrock:InvokeModelWithResponseStream",
	"bedrock:Converse",
	"bedrock:ConverseStream",
}

// sampleBedrockARN is what a typical invoke targets; resource patterns are matched against it.
const sampleBedrockARN = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-model"

type strOrList []string

func (s *strOrList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

type Statement struct {
	Effect      string          `json:"Effect"`
	Action      strOrList       `json:"Action"`
	NotAction   strOrList       `json:"NotAction"`
	Resource    strOrList       `json:"Resource"`
	NotResource strOrList       `json:"NotResource"`
	Principal   json.RawMessage `json:"Principal"`
	Condition   json.RawMessage `json:"Condition"`
}

type stmtList []Statement

func (s *stmtList) UnmarshalJSON(b []byte) error {
	var one Statement
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = []Statement{one}
		return nil
	}
	var many []Statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

type PolicyDoc struct {
	Statement stmtList `json:"Statement"`
}

// ParseDoc accepts URL-encoded (as IAM returns it) or plain JSON.
func ParseDoc(raw string) (PolicyDoc, error) {
	var d PolicyDoc
	if strings.HasPrefix(strings.TrimSpace(raw), "%7B") || strings.Contains(raw, "%22") {
		if u, err := url.QueryUnescape(raw); err == nil {
			raw = u
		}
	}
	err := json.Unmarshal([]byte(raw), &d)
	return d, err
}

// wildMatch: IAM-style glob with * and ?, case-insensitive (actions) or not.
func wildMatch(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(s) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[t]) {
			p++
			t++
		} else if p < len(pattern) && pattern[p] == '*' {
			star, mark = p, t
			p++
		} else if star >= 0 {
			p = star + 1
			mark++
			t = mark
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func anyMatch(patterns []string, s string, fold bool) bool {
	for _, p := range patterns {
		if wildMatch(p, s, fold) {
			return true
		}
	}
	return false
}

func (st Statement) coversInvoke() bool {
	for _, a := range InvokeActions {
		if len(st.Action) > 0 && anyMatch(st.Action, a, true) {
			return true
		}
		if len(st.NotAction) > 0 && !anyMatch(st.NotAction, a, true) {
			return true
		}
	}
	return false
}

func (st Statement) coversBedrockResource() bool {
	if len(st.NotResource) > 0 {
		return !anyMatch(st.NotResource, sampleBedrockARN, false)
	}
	for _, r := range st.Resource {
		if wildMatch(r, sampleBedrockARN, false) || strings.HasPrefix(r, "arn:aws:bedrock:") {
			return true
		}
	}
	return false
}

func hasCondition(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "{}"
}

// Grant is the result of evaluating a set of policies for Bedrock invoke.
type Grant struct {
	Allowed     bool
	Conditional bool     // every allowing statement carries a Condition
	Via         []string // policy names that allow it
}

type NamedDoc struct {
	Name string
	Doc  string
}

// EvaluateInvoke: does this set of identity policies allow Bedrock invoke?
// Unconditional explicit Denies on all resources win. Conditions are not
// evaluated; they are reported as "conditional". This is a heuristic, not
// the full IAM evaluation engine.
func EvaluateInvoke(docs []NamedDoc) Grant {
	var g Grant
	unconditional := false
	for _, nd := range docs {
		d, err := ParseDoc(nd.Doc)
		if err != nil {
			continue
		}
		for _, st := range d.Statement {
			if !st.coversInvoke() || !st.coversBedrockResource() {
				continue
			}
			switch strings.ToLower(st.Effect) {
			case "deny":
				if !hasCondition(st.Condition) && denyAllBedrock(st) {
					return Grant{}
				}
			case "allow":
				g.Allowed = true
				if !hasCondition(st.Condition) {
					unconditional = true
				}
				if !contains(g.Via, nd.Name) {
					g.Via = append(g.Via, nd.Name)
				}
			}
		}
	}
	g.Conditional = g.Allowed && !unconditional
	return g
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// TrustRisk inspects a role trust policy. It returns "public" if any Allow
// statement trusts "*" without a Condition, "external" if it trusts an AWS
// principal outside ownAccount without a Condition (e.g. sts:ExternalId),
// and "" otherwise.
func TrustRisk(raw, ownAccount string) (risk string, who []string) {
	d, err := ParseDoc(raw)
	if err != nil {
		return "", nil
	}
	for _, st := range d.Statement {
		if !strings.EqualFold(st.Effect, "allow") || hasCondition(st.Condition) {
			continue
		}
		var star string
		if json.Unmarshal(st.Principal, &star) == nil && star == "*" {
			return "public", []string{"*"}
		}
		var p struct {
			AWS strOrList `json:"AWS"`
		}
		if json.Unmarshal(st.Principal, &p) != nil {
			continue
		}
		for _, a := range p.AWS {
			if a == "*" {
				return "public", []string{"*"}
			}
			acct := a
			if strings.HasPrefix(a, "arn:") {
				parts := strings.Split(a, ":")
				if len(parts) > 4 {
					acct = parts[4]
				}
			}
			if acct != ownAccount {
				who = append(who, a)
			}
		}
	}
	if len(who) > 0 {
		return "external", who
	}
	return "", nil
}

func denyAllBedrock(st Statement) bool {
	if len(st.NotResource) > 0 {
		return false
	}
	for _, r := range st.Resource {
		if r == "*" || strings.HasPrefix(r, "arn:aws:bedrock:*") {
			return true
		}
	}
	return false
}

// TrustServices returns AWS service principals (e.g. ec2.amazonaws.com) a role trusts.
func TrustServices(raw string) []string {
	d, err := ParseDoc(raw)
	if err != nil {
		return nil
	}
	var out []string
	for _, st := range d.Statement {
		if !strings.EqualFold(st.Effect, "allow") {
			continue
		}
		var p struct {
			Service strOrList `json:"Service"`
		}
		if json.Unmarshal(st.Principal, &p) == nil {
			out = append(out, p.Service...)
		}
	}
	return out
}
