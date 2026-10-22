package netdiag

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// WriteText renders the report for humans. color enables ANSI colors.
func (r *Report) WriteText(w io.Writer, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}
	fmt.Fprintf(w, "%s %s\n", paint(ansiBold, "netdiag"), r.Target)
	fmt.Fprintf(w, "%s\n\n", paint(ansiDim, fmt.Sprintf("target: %s port %s (%s), path %s", r.Host, r.Port, r.Scheme, r.Path)))

	indent := strings.Repeat(" ", 18)
	for _, s := range r.Stages {
		mark, c := "?", ""
		switch s.Status {
		case StatusOK:
			mark, c = "✔", ansiGreen
		case StatusWarn:
			mark, c = "!", ansiYellow
		case StatusFail:
			mark, c = "✘", ansiRed
		case StatusSkipped:
			mark, c = "-", ansiDim
		}
		dur := ""
		if s.Status != StatusSkipped || s.Duration > 0 {
			dur = roundDur(s.Duration)
		}
		if s.Status == StatusSkipped && s.Stage == StageDNS {
			dur = ""
		}
		line := fmt.Sprintf(" %s %-5s %9s  %s", mark, s.Stage, dur, s.Summary)
		fmt.Fprintln(w, paint(c, line))
		for _, d := range s.Details {
			fmt.Fprintln(w, indent+paint(ansiDim, d))
		}
		if s.Hint != "" && (s.Status == StatusFail || s.Status == StatusWarn) {
			fmt.Fprintln(w, indent+paint(ansiCyan, "hint: "+s.Hint))
		}
	}
	fmt.Fprintln(w)

	var verdict string
	switch {
	case r.OK:
		verdict = paint(ansiGreen+ansiBold, "OK") + fmt.Sprintf(": all stages passed in %s", roundDur(r.Total))
		var warns []string
		for _, s := range r.Stages {
			if s.Status == StatusWarn {
				warns = append(warns, fmt.Sprintf("%s (%s)", s.Stage, s.Code))
			}
		}
		if len(warns) > 0 {
			verdict += paint(ansiYellow, ", with warnings: "+strings.Join(warns, ", "))
		}
	default:
		failed := r.Stage(r.FailedStage)
		verdict = paint(ansiRed+ansiBold, "FAILED") + fmt.Sprintf(" at the %s stage", r.FailedStage)
		if failed != nil && failed.Code != "" {
			verdict += " (" + failed.Code + ")"
		}
	}
	if q := r.Stage(StageQUIC); q != nil && q.Status == StatusFail {
		verdict += paint(ansiYellow, "; QUIC/HTTP3 path failed ("+q.Code+")")
	}
	fmt.Fprintf(w, " %s %s\n", paint(ansiBold, "result:"), verdict)
}

// WriteJSON renders the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
