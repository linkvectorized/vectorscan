package output

import (
	"fmt"

	"github.com/linkvectorized/vectorscan/pkg/models"
)

// PrintMarkdown outputs the report in Markdown format
func PrintMarkdown(report *models.Report) {
	fmt.Println("# VECTORSCAN — System Security Audit Report")
	fmt.Println("*Big brother is always watching. Question everything. Especially the government.*")
	fmt.Println()

	// Summary section
	fmt.Println("## Summary")
	fmt.Println()
	fmt.Printf("- **Hostname:** %s\n", report.Hostname)
	fmt.Printf("- **Platform:** %s\n", report.Platform)
	fmt.Printf("- **OS Version:** %s\n", report.OSVersion)
	fmt.Printf("- **Scan Date:** %s\n", report.ScanDate.Format("2006-01-02 15:04:05"))
	fmt.Printf("- **Scan Duration:** %dms\n", report.ScanTime.Milliseconds())
	fmt.Println()

	// Security score section
	fmt.Println("## Security Score")
	fmt.Println()
	fmt.Printf("| Metric | Value |\n")
	fmt.Printf("|--------|-------|\n")
	fmt.Printf("| Score | %d%% |\n", report.SecurityScore)
	fmt.Printf("| Points | %d/%d |\n", report.EarnedPoints, report.MaxPoints)
	fmt.Printf("| Level | %s |\n", report.SecurityLevel())
	fmt.Println()

	// Findings summary
	fmt.Println("## Findings Summary")
	fmt.Println()
	fmt.Printf("| Severity | Count |\n")
	fmt.Printf("|----------|-------|\n")
	fmt.Printf("| Critical | %d |\n", report.Critical)
	fmt.Printf("| High | %d |\n", report.High)
	fmt.Printf("| Medium | %d |\n", report.Medium)
	fmt.Printf("| Low | %d |\n", report.Low)
	fmt.Printf("| Info | %d |\n", report.Info)
	fmt.Printf("| **Total** | **%d** |\n", report.TotalFindings)
	fmt.Println()

	// Detailed findings
	if report.TotalFindings > 0 {
		fmt.Println("## Detailed Findings")
		fmt.Println()

		for _, finding := range report.Findings {
			fmt.Printf("### %s - %s\n", finding.ID, finding.Title)
			fmt.Println()
			fmt.Printf("**Category:** %s\n\n", finding.Category)
			fmt.Printf("**Severity:** %s\n\n", finding.Severity)
			fmt.Printf("**Description:**\n\n%s\n\n", finding.Description)
			fmt.Printf("**Remediation:**\n\n%s\n\n", finding.Remediation)

			if len(finding.Evidence) > 0 {
				fmt.Println("**Evidence:**")
				fmt.Println()
				for _, e := range finding.Evidence {
					fmt.Printf("- %s\n", e)
				}
				fmt.Println()
			}
		}
	} else {
		fmt.Println("## Detailed Findings")
		fmt.Println()
		fmt.Println("✨ No security issues detected!")
		fmt.Println()
	}

	// Recommendations
	if report.SecurityScore < 60 {
		fmt.Println("## ⚠️  Recommendations")
		fmt.Println()
		fmt.Println("1. Address CRITICAL and HIGH severity issues immediately")
		fmt.Println("2. Implement secure defaults for system configuration")
		fmt.Println("3. Enable security features (firewall, SIP, Gatekeeper)")
		fmt.Println("4. Regularly update system and software")
		fmt.Println()
	}
}
