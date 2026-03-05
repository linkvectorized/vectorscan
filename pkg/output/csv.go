package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/linkvectorized/vectorscan/pkg/models"
)

// PrintCSV outputs the report in CSV format
func PrintCSV(report *models.Report) {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	// Write header
	headers := []string{
		"ID",
		"Category",
		"Severity",
		"Title",
		"Description",
		"Remediation",
		"Evidence",
		"Timestamp",
	}
	if err := w.Write(headers); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSV header: %v\n", err)
		return
	}

	// Write findings as rows
	for _, finding := range report.Findings {
		evidence := strings.Join(finding.Evidence, "; ")
		row := []string{
			finding.ID,
			finding.Category,
			finding.Severity,
			finding.Title,
			finding.Description,
			finding.Remediation,
			evidence,
			finding.Timestamp.Format("2006-01-02 15:04:05"),
		}
		if err := w.Write(row); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSV row: %v\n", err)
			return
		}
	}

	// Write summary at the end
	fmt.Fprintf(os.Stderr, "\nSummary:\n")
	fmt.Fprintf(os.Stderr, "Hostname: %s\n", report.Hostname)
	fmt.Fprintf(os.Stderr, "Platform: %s\n", report.Platform)
	fmt.Fprintf(os.Stderr, "OS Version: %s\n", report.OSVersion)
	fmt.Fprintf(os.Stderr, "Security Score: %d%% (%d/%d points)\n", report.SecurityScore, report.EarnedPoints, report.MaxPoints)
	fmt.Fprintf(os.Stderr, "Security Level: %s\n", report.SecurityLevel())
	fmt.Fprintf(os.Stderr, "Total Findings: %d\n", report.TotalFindings)
	fmt.Fprintf(os.Stderr, "  Critical: %d\n", report.Critical)
	fmt.Fprintf(os.Stderr, "  High: %d\n", report.High)
	fmt.Fprintf(os.Stderr, "  Medium: %d\n", report.Medium)
	fmt.Fprintf(os.Stderr, "  Low: %d\n", report.Low)
	fmt.Fprintf(os.Stderr, "  Info: %d\n", report.Info)
}
