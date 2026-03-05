package models

import "time"

// Severity levels for findings
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Finding represents a single security discovery
type Finding struct {
	ID          string    `json:"id"`          // Unique identifier (e.g., "PERM-001")
	Category    string    `json:"category"`    // permissions, passwords, system, configs, network, software
	Severity    string    `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Title       string    `json:"title"`       // "SSH allows root login"
	Description string    `json:"description"` // Detailed explanation
	Remediation string    `json:"remediation"` // How to fix it
	Evidence    []string  `json:"evidence"`    // Proof: file paths, outputs, values
	Passed      bool      `json:"passed"`      // True if check passed (positive finding)
	Skipped     bool      `json:"skipped"`     // True if check was skipped (timeout, insufficient privileges)
	Timestamp   time.Time `json:"timestamp"`
}

// SeverityWeight returns the severity weight for scoring
// Critical=4, High=3, Medium=2, Low=1, Info=0
func (f *Finding) SeverityWeight() int {
	switch f.Severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return 0
	}
}
