package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/linkvectorized/vectorscan/pkg/models"
)

//go:embed index.html
var indexHTML embed.FS

// ReportResponse wraps the report with additional server-computed fields
type ReportResponse struct {
	Findings      []models.Finding `json:"findings"`
	ScanDate      time.Time        `json:"scan_date"`
	OSVersion     string           `json:"os_version"`
	Hostname      string           `json:"hostname"`
	Platform      string           `json:"platform"`
	Critical      int              `json:"critical"`
	High          int              `json:"high"`
	Medium        int              `json:"medium"`
	Low           int              `json:"low"`
	Info          int              `json:"info"`
	Enabled       int              `json:"enabled"`
	TotalFindings int              `json:"total_findings"`
	PassingChecks int              `json:"passing_checks"`
	SecurityScore int              `json:"security_score"`
	ScanTimeMs    int64            `json:"scan_time_ms"` // Computed from ScanTime duration
	SecurityLevel string           `json:"security_level"`
}

// Serve starts the HTTP server with the given report
func Serve(report *models.Report, port int) error {
	// Create the response envelope
	response := ReportResponse{
		Findings:      report.Findings,
		ScanDate:      report.ScanDate,
		OSVersion:     report.OSVersion,
		Hostname:      report.Hostname,
		Platform:      report.Platform,
		Critical:      report.Critical,
		High:          report.High,
		Medium:        report.Medium,
		Low:           report.Low,
		Info:          report.Info,
		Enabled:       report.Enabled,
		TotalFindings: report.TotalFindings,
		PassingChecks: report.PassingChecks,
		SecurityScore: report.SecurityScore,
		ScanTimeMs:    report.ScanTime.Milliseconds(),
		SecurityLevel: report.SecurityLevel(),
	}

	// Set up routes
	mux := http.NewServeMux()

	// Serve index.html at /
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data, _ := indexHTML.ReadFile("index.html")
		w.Write(data)
	})

	// Serve API endpoint
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Create server
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
	}()

	// Give server time to start
	time.Sleep(300 * time.Millisecond)

	// Print message and open browser
	url := fmt.Sprintf("http://localhost:%d", port)
	fmt.Fprintf(os.Stderr, "\n✓ Scan complete! Opening dashboard at %s\n", url)
	time.Sleep(500 * time.Millisecond) // Brief pause before opening
	openBrowser(url)

	// Wait for interrupt signal
	<-sigChan
	fmt.Fprintf(os.Stderr, "\nShutting down server...\n")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
		return err
	}

	fmt.Fprintf(os.Stderr, "Server stopped.\n")
	return nil
}

// openBrowser attempts to open the URL in the default browser
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("start", url)
	default:
		return
	}
	_ = cmd.Run() // Ignore errors, user can manually open browser
}
