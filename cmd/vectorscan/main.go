package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
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

// goarch is baked in at compile time via runtime.GOARCH
var goarch = runtime.GOARCH

func main() {
	// Define CLI flags
	outputFormat := flag.String("output", "table", "Output format (table, json, csv, markdown)")
	versionFlag := flag.Bool("version", false, "Show version")
	helpFlag := flag.Bool("help", false, "Show help")
	// serveFlag := flag.Bool("serve", false, "Start the web dashboard server") // TODO: uncomment when frontend ready
	// portFlag := flag.Int("port", 8080, "Dashboard server port") // TODO: uncomment when frontend ready

	flag.Parse()

	// Handle version flag
	if *versionFlag {
		fmt.Printf("vectorscan v%s\n", version)
		os.Exit(0)
	}

	// Handle help flag
	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	// Validate output format
	if *outputFormat != "table" && *outputFormat != "json" && *outputFormat != "csv" && *outputFormat != "markdown" {
		fmt.Fprintf(os.Stderr, "Error: unsupported output format '%s'\n", *outputFormat)
		fmt.Fprintf(os.Stderr, "Supported formats: table, json, csv, markdown\n")
		os.Exit(1)
	}

	// Check if running as root (recommended for accurate results)
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Warning: not running as root. Some checks may be incomplete or inaccurate.\n\n")
	}

	// Check for updates in background while scan runs
	updateCh := make(chan string, 1)
	go func() {
		updateCh <- checkForUpdate()
	}()

	// Create scanner
	s, err := scanner.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scanner: %v\n", err)
		os.Exit(1)
	}

	// Run scan with progress tracking and timeout
	// Use timeout of 5 minutes for entire scan to prevent hanging on slow checks
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var report *models.Report
	var scanErr error
	var wg sync.WaitGroup

	// Start progress goroutine
	stopProgress := make(chan bool, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		showProgress(s, stopProgress)
	}()

	// Run the actual scan
	report, scanErr = s.Scan(ctx)

	// Stop progress display
	stopProgress <- true
	wg.Wait()

	// Clear the progress line
	fmt.Fprint(os.Stderr, "\r")

	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", scanErr)
		os.Exit(1)
	}

	// Dashboard server disabled for now - will implement frontend tomorrow
	// if *serveFlag {
	// 	if err := web.Serve(report, *portFlag); err != nil {
	// 		fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
	// 		os.Exit(1)
	// 	}
	// 	return
	// }

	// Apply update if one was found
	if msg := <-updateCh; msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}

	// Output results based on format
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

// checkForUpdate fetches the latest release tag from GitHub and self-updates if behind.
// Returns a status message or empty string if already current.
func checkForUpdate() string {
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

	exe, err := os.Executable()
	if err != nil {
		return ""
	}

	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/vectorscan-darwin-%s", repo, release.TagName, goarch)

	resp2, err := client.Get(url)
	if err != nil || resp2.StatusCode != 200 {
		return ""
	}
	defer resp2.Body.Close()

	tmp, err := os.CreateTemp("", "vectorscan-update-*")
	if err != nil {
		return ""
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.ReadFrom(resp2.Body); err != nil {
		tmp.Close()
		return ""
	}
	tmp.Close()

	if err := os.Chmod(tmp.Name(), 0755); err != nil {
		return ""
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return ""
	}

	return fmt.Sprintf("Updated vectorscan v%s → v%s", current, latest)
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
  - macOS only (Linux/Windows support coming soon)
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
			// Display progress once per check update, no animation
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

	// Pad check name to consistent width and truncate
	checkNamePadded := truncate(checkName, 50)
	checkNamePadded = fmt.Sprintf("%-50s", checkNamePadded)

	// Only show spinner if provided
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
