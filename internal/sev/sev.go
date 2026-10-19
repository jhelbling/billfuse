// Package sev defines the severity scale shared by all audits.
package sev

import "strings"

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func Parse(s string) (Severity, bool) {
	switch strings.ToLower(s) {
	case "info":
		return Info, true
	case "low":
		return Low, true
	case "medium":
		return Medium, true
	case "high":
		return High, true
	case "critical":
		return Critical, true
	}
	return 0, false
}
