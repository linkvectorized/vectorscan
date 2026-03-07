package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/linkvectorized/vectorscan/pkg/models"
	"github.com/linkvectorized/vectorscan/pkg/output"
	"github.com/linkvectorized/vectorscan/pkg/scanner"
	// "github.com/linkvectorized/vectorscan/pkg/web" // TODO: uncomment when frontend ready
)

var version = "dev"

const repo = "linkvectorized/vectorscan"

func main() {
	outputFormat := flag.String("output", "table", "Output format (table, json, csv, markdown)")
	versionFlag := flag.Bool("version", false, "Show version")
	helpFlag := flag.Bool("help", false, "Show help")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("vectorscan v%s\n", version)
		os.Exit(0)
	}

	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	if *outputFormat != "table" && *outputFormat != "json" && *outputFormat != "csv" && *outputFormat != "markdown" {
		fmt.Fprintf(os.Stderr, "Error: unsupported output format '%s'\n", *outputFormat)
		fmt.Fprintf(os.Stderr, "Supported formats: table, json, csv, markdown\n")
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Warning: not running as root. Some checks may be incomplete or inaccurate.\n\n")
	}

	// Check for newer version in background while scan runs
	updateCh := make(chan string, 1)
	go func() {
		updateCh <- checkLatestVersion()
	}()

	s, err := scanner.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scanner: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var report *models.Report
	var scanErr error
	var wg sync.WaitGroup

	stopProgress := make(chan bool, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		showProgress(s, stopProgress)
	}()

	report, scanErr = s.Scan(ctx)

	stopProgress <- true
	wg.Wait()

	fmt.Fprint(os.Stderr, "\r")

	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", scanErr)
		os.Exit(1)
	}

	// Print update notice if a newer version exists
	if notice := <-updateCh; notice != "" {
		fmt.Fprintln(os.Stderr, notice)
	}

	switch *outputFormat {
	case "table":
		output.PrintTable(report)
	case "json":
		output.PrintJSON(report)
	case "csv":
		output.PrintCSV(report)
	case "markdown":
		output.PrintMarkdown(report)
	}
}

// checkLatestVersion checks GitHub for a newer release and returns a notice string if one exists.
func checkLatestVersion() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ""
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(version, "v")

	if latest == "" || latest == current || current == "dev" {
		return ""
	}

	return fmt.Sprintf("Update available: v%s → v%s  |  curl -fsSL https://raw.githubusercontent.com/%s/master/install.sh | bash", current, latest, repo)
}

func printHelp() {
	fmt.Printf(`vectorscan v%s - System Security Audit Tool

Usage:
  vectorscan [options]

Options:
  -output string     Output format: table, json, csv, markdown (default: table)
  -version           Show version
  -help              Show this help message

Examples:
  vectorscan
  sudo vectorscan
  vectorscan -output json
  vectorscan -output markdown

Notes:
  - macOS and Linux supported
  - Run with sudo for most accurate results
  - Some checks may require elevated privileges
`, version)
}

func showProgress(s *scanner.Scanner, stop chan bool) {
	progressChan := s.ProgressChan()
	var current, total int
	var lastCheck string

	for {
		select {
		case <-stop:
			return
		case progress, ok := <-progressChan:
			if !ok {
				return
			}
			current = progress.CurrentCheck
			total = progress.TotalChecks
			lastCheck = progress.CheckName
			displayProgressBar(current, total, lastCheck, "")
		}
	}
}

func displayProgressBar(current, total int, checkName, spinner string) {
	barWidth := 40
	percentage := 0
	if total > 0 {
		percentage = (current * 100) / total
	}
	filled := 0
	if total > 0 {
		filled = (current * barWidth) / total
	}
	if filled > barWidth {
		filled = barWidth
	}

	bar := "["
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "="
		} else {
			bar += " "
		}
	}
	bar += "]"

	checkNamePadded := truncate(checkName, 50)
	checkNamePadded = fmt.Sprintf("%-50s", checkNamePadded)

	spinnerPrefix := ""
	if spinner != "" {
		spinnerPrefix = spinner + " "
	}

	displayText := fmt.Sprintf("\r%s%s %3d%% (%2d/%2d) %s", spinnerPrefix, bar, percentage, current, total, checkNamePadded)
	fmt.Fprint(os.Stderr, displayText)
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) > maxLen {
		return string(runes[:maxLen-3]) + "..."
	}
	return s
}
