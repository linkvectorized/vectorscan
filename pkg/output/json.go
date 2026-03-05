package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/linkvectorized/vectorscan/pkg/models"
)

// PrintJSON outputs the report in JSON format
func PrintJSON(report *models.Report) {
	data := map[string]interface{}{
		"scan_date":        report.ScanDate.Format("2006-01-02T15:04:05Z07:00"),
		"scan_time_ms":     report.ScanTime.Milliseconds(),
		"hostname":         report.Hostname,
		"platform":         report.Platform,
		"os_version":       report.OSVersion,
		"security_score":   report.SecurityScore,
		"security_level":   report.SecurityLevel(),
		"score_calculation": fmt.Sprintf("%d/%d points (%d%%) — %d of %d checks passing", report.EarnedPoints, report.MaxPoints, report.SecurityScore, report.PassingChecks, report.TotalFindings),
		"earned_points":    report.EarnedPoints,
		"max_points":       report.MaxPoints,
		"total_findings":   report.TotalFindings,
		"passing_checks":   report.PassingChecks,
		"critical":         report.Critical,
		"high":             report.High,
		"medium":           report.Medium,
		"low":              report.Low,
		"info":             report.Info,
		"enabled":          report.Enabled,
		"findings":         report.Findings,
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		return
	}

	fmt.Println(string(jsonBytes))
}
