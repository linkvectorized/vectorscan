package output

import (
	"fmt"
	"strings"

	"github.com/linkvectorized/vectorscan/pkg/models"
)

// PrintTable prints a human-readable report
func PrintTable(report *models.Report) {
	cyan := "\x1b[0;36m"
	yellow := "\x1b[1;33m"
	nc := "\x1b[0m"

	fmt.Println()
	fmt.Printf("%s", cyan)
	fmt.Println("  ╔══════════════════════════════════════════════════════════╗")
	fmt.Println("  ║            VECTORSCAN — System Security Audit            ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("%s", nc)
	fmt.Printf("  %sBig brother is always watching. Question everything. Especially the government.%s\n\n", yellow, nc)

	// Summary section
	fmt.Printf("Host:            %s\n", report.Hostname)
	fmt.Printf("Platform:        %s\n", report.Platform)
	fmt.Printf("OS Version:      %s\n", report.OSVersion)
	fmt.Printf("Scan Date:       %s\n", report.ScanDate.Format("2006-01-02 15:04:05"))
	fmt.Printf("Scan Duration:   %dms\n", report.ScanTime.Milliseconds())
	fmt.Println()

	// Security score
	fmt.Println("┌─ Security Score ─────────────────────────────────────────┐")
	scoreBar := generateScoreBar(report.SecurityScore)
	fmt.Printf("│ %s [%d%%] %s\n", scoreBar, report.SecurityScore, report.SecurityLevel())
	fmt.Printf("│ %d of %d checks passing | %d/%d points\n", report.PassingChecks, report.TotalFindings, report.EarnedPoints, report.MaxPoints)
	fmt.Println("└──────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Findings summary
	fmt.Println("Findings Summary:")
	if report.Critical > 0 {
		fmt.Printf("  🔴 Critical:  %d\n", report.Critical)
	}
	if report.High > 0 {
		fmt.Printf("  🟠 High:      %d\n", report.High)
	}
	if report.Medium > 0 {
		fmt.Printf("  🟡 Medium:    %d\n", report.Medium)
	}
	if report.Low > 0 {
		fmt.Printf("  🟢 Low:       %d\n", report.Low)
	}
	if report.Info > 0 {
		fmt.Printf("  ℹ️  Info:      %d\n", report.Info)
	}
	if report.Enabled > 0 {
		fmt.Printf("  ✅ Enabled:   %d\n", report.Enabled)
	}
	fmt.Printf("  📊 Total:     %d\n", report.TotalFindings)
	fmt.Println()

	// Detailed findings
	if report.TotalFindings > 0 {
		fmt.Println("┌─ Detailed Findings ───────────────────────────────────────┐")
		fmt.Println()

		for _, f := range report.Findings {
			printFinding(f)
		}
		fmt.Println("└──────────────────────────────────────────────────────────┘")
	} else {
		fmt.Println("✨ No security issues detected!")
	}
	fmt.Println()

	// Recommendations
	if report.SecurityScore < 60 {
		fmt.Println("⚠️  Recommendations:")
		fmt.Println("  1. Address CRITICAL and HIGH severity issues immediately")
		fmt.Println("  2. Implement secure defaults for system configuration")
		fmt.Println("  3. Enable security features (firewall, SIP, Gatekeeper)")
		fmt.Println("  4. Regularly update system and software")
		fmt.Println()
	}
}

func printFinding(f models.Finding) {
	severity := severityEmoji(f.Severity)
	title := f.Title

	// Highlight positive findings (enabled features) in green
	if f.Passed {
		title = fmt.Sprintf("\x1b[32m%s\x1b[0m", f.Title)
	}

	fmt.Printf("%s [%s] %s\n", severity, f.ID, title)
	fmt.Printf("   Category:    %s\n", f.Category)
	fmt.Printf("   Severity:    %s\n", f.Severity)
	fmt.Printf("   Description: %s\n", f.Description)
	fmt.Printf("   Remediation: %s\n", f.Remediation)
	if len(f.Evidence) > 0 {
		fmt.Printf("   Evidence:\n")
		for _, e := range f.Evidence {
			fmt.Printf("     • %s\n", e)
		}
	}
	fmt.Println()
}

func severityEmoji(severity string) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🟢"
	case models.SeverityInfo:
		return "ℹ️"
	default:
		return "?"
	}
}

func generateScoreBar(score int) string {
	filled := (score / 10)
	empty := 10 - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	// Color based on score
	if score >= 90 {
		return fmt.Sprintf("\x1b[32m%s\x1b[0m", bar) // Green
	} else if score >= 75 {
		return fmt.Sprintf("\x1b[33m%s\x1b[0m", bar) // Yellow
	} else if score >= 60 {
		return fmt.Sprintf("\x1b[33m%s\x1b[0m", bar) // Orange
	} else if score >= 45 {
		return fmt.Sprintf("\x1b[31m%s\x1b[0m", bar) // Red
	} else {
		return fmt.Sprintf("\x1b[91m%s\x1b[0m", bar) // Bright red
	}
}
