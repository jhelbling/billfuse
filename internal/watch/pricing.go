package watch

import (
	"encoding/json"
	"os"
	"strings"
)

// Price is USD per 1M tokens, or per 1k requests for request-priced APIs.
type Price struct {
	Match  string  `json:"match"` // lowercase substring of the model id
	In     float64 `json:"in_per_mtok"`
	Out    float64 `json:"out_per_mtok"`
	PerKRq float64 `json:"per_1k_requests,omitempty"`
}

// Pricing is an ordered list; the first matching entry wins.
// Defaults are list prices as of late 2026 and are ESTIMATES - override with --prices.
type Pricing struct {
	Models         []Price `json:"models"`
	UnknownIn      float64 `json:"unknown_in_per_mtok"` // deliberately high: alert early on unknown models
	UnknownOut     float64 `json:"unknown_out_per_mtok"`
	GeminiPerKReq  float64 `json:"gemini_api_per_1k_requests"`
	VertexPerKReq  float64 `json:"vertex_per_1k_requests_without_tokens"`
	BillableKeyAPI float64 `json:"other_per_1k_requests"`
}

func DefaultPricing() Pricing {
	return Pricing{
		Models: []Price{
			{Match: "opus-4-5", In: 5, Out: 25},
			{Match: "opus-4-6", In: 5, Out: 25},
			{Match: "opus", In: 15, Out: 75},
			{Match: "sonnet", In: 3, Out: 15},
			{Match: "claude-3-haiku", In: 0.25, Out: 1.25},
			{Match: "haiku-4", In: 1, Out: 5},
			{Match: "haiku", In: 0.8, Out: 4},
			{Match: "nova-premier", In: 2.5, Out: 12.5},
			{Match: "nova-pro", In: 0.8, Out: 3.2},
			{Match: "nova-lite", In: 0.06, Out: 0.24},
			{Match: "nova-micro", In: 0.035, Out: 0.14},
			{Match: "llama", In: 0.72, Out: 0.72},
			{Match: "mistral-large", In: 2, Out: 6},
			{Match: "deepseek", In: 1.35, Out: 5.4},
			{Match: "embed", In: 0.1, Out: 0},
			{Match: "gemini-2.5-flash-lite", In: 0.1, Out: 0.4},
			{Match: "gemini-2.5-flash", In: 0.3, Out: 2.5},
			{Match: "gemini-2.5-pro", In: 1.25, Out: 10},
			{Match: "gemini-3", In: 2, Out: 12},
			{Match: "gemini", In: 2, Out: 12},
		},
		UnknownIn:     15,
		UnknownOut:    75,
		GeminiPerKReq: 10, // ~ $0.01 per request: a mid-size Gemini Pro call
		VertexPerKReq: 10,
	}
}

func LoadPricing(path string) (Pricing, error) {
	p := DefaultPricing()
	if path == "" {
		return p, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	var over Pricing
	if err := json.Unmarshal(b, &over); err != nil {
		return p, err
	}
	if len(over.Models) > 0 {
		p.Models = append(over.Models, p.Models...) // user entries take precedence
	}
	if over.UnknownIn > 0 {
		p.UnknownIn = over.UnknownIn
	}
	if over.UnknownOut > 0 {
		p.UnknownOut = over.UnknownOut
	}
	if over.GeminiPerKReq > 0 {
		p.GeminiPerKReq = over.GeminiPerKReq
	}
	if over.VertexPerKReq > 0 {
		p.VertexPerKReq = over.VertexPerKReq
	}
	return p, nil
}

// TokenCost returns the estimated USD cost and whether the model was known.
func (p Pricing) TokenCost(model string, in, out float64) (float64, bool) {
	m := strings.ToLower(model)
	for _, e := range p.Models {
		if strings.Contains(m, e.Match) {
			return in/1e6*e.In + out/1e6*e.Out, true
		}
	}
	return in/1e6*p.UnknownIn + out/1e6*p.UnknownOut, false
}
