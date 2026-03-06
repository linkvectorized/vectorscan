package models

import (
	"time"
)

// Report represents the complete scan results
type Report struct {
	Findings      []Finding     `json:"findings"`
	ScanTime      time.Duration `json:"-"`
	ScanDate      time.Time     `json:"scan_date"`
	OSVersion     string        `json:"os_version"`
	Hostname      string        `json:"hostname"`
	Platform      string        `json:"platform"` // macos, linux, windows

	// Summary counts
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
	Enabled       int `json:"enabled"` // Positive findings (enabled security features)
	TotalFindings int `json:"total_findings"`
	PassingChecks int `json:"passing_checks"` // Number of checks that passed

	// Weighted security score
	SecurityScore int `json:"security_score"` // 0-100 percentage
	EarnedPoints  int `json:"earned_points"`  // Points earned (max - deductions)
	MaxPoints     int `json:"max_points"`     // Maximum possible points
}

// CalculateScore computes a weighted security score.
// Each check is worth 4 points (max severity weight).
// Failing checks deduct based on severity: Critical=4, High=3, Medium=2, Low=1, Info=0.
// Skipped checks (timeouts, insufficient privileges) are excluded from scoring.
func (r *Report) CalculateScore() {
	if r.TotalFindings == 0 {
		r.SecurityScore = 100
		r.PassingChecks = 0
		r.EarnedPoints = 0
		r.MaxPoints = 0
		return
	}

	passingCount := 0
	skippedCount := 0
	deductions := 0

	for _, finding := range r.Findings {
		if finding.Skipped {
			skippedCount++
		} else if finding.Passed {
			passingCount++
		} else {
			deductions += finding.SeverityWeight()
		}
	}

	r.PassingChecks = passingCount
	scoredFindings := r.TotalFindings - skippedCount
	if scoredFindings == 0 {
		r.SecurityScore = 100
		r.MaxPoints = 0
		r.EarnedPoints = 0
		return
	}
	r.MaxPoints = scoredFindings * 4
	r.EarnedPoints = r.MaxPoints - deductions

	if r.EarnedPoints < 0 {
		r.EarnedPoints = 0
	}

	r.SecurityScore = (r.EarnedPoints * 100) / r.MaxPoints

	if r.SecurityScore < 0 {
		r.SecurityScore = 0
	}
	if r.SecurityScore > 100 {
		r.SecurityScore = 100
	}
}

// Summarize counts findings by severity
func (r *Report) Summarize() {
	r.Critical = 0
	r.High = 0
	r.Medium = 0
	r.Low = 0
	r.Info = 0
	r.Enabled = 0

	for _, f := range r.Findings {
		if f.Skipped {
			continue // Skipped findings don't count as issues or passing checks
		}
		if f.Passed {
			r.Enabled++
			continue
		}

		switch f.Severity {
		case SeverityCritical:
			r.Critical++
		case SeverityHigh:
			r.High++
		case SeverityMedium:
			r.Medium++
		case SeverityLow:
			r.Low++
		case SeverityInfo:
			r.Info++
		}
	}

	r.TotalFindings = len(r.Findings)
	r.CalculateScore()
}

// SecurityLevel returns text representation of score
// Based on percentage of passing checks
func (r *Report) SecurityLevel() string {
	switch {
	case r.SecurityScore >= 90:
		return "Excellent (90%+ checks passing)"
	case r.SecurityScore >= 75:
		return "Good (75%+ checks passing)"
	case r.SecurityScore >= 60:
		return "Fair (60%+ checks passing)"
	case r.SecurityScore >= 45:
		return "Poor (45%+ checks passing)"
	default:
		return "Critical (<45% checks passing)"
	}
}
