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
	"sync/atomic"
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
	ScanTimeMs    int64            `json:"scan_time_ms"`
	SecurityLevel string           `json:"security_level"`
}

const (
	pingInterval  = 15 * time.Second // browser pings this often
	idleTimeout   = 45 * time.Second // server shuts down after this long with no ping
)

// Serve starts the HTTP server with the given report.
// The server detaches from the terminal so it can be closed safely.
// It shuts down automatically when the browser tab is closed.
func Serve(report *models.Report, port int) error {
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

	// lastPing tracks when the browser last checked in.
	// Initialised to now so the grace period starts from server start.
	var lastPing atomic.Int64
	lastPing.Store(time.Now().UnixNano())

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data, _ := indexHTML.ReadFile("index.html")
		w.Write(data)
	})

	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// /ping is called by the browser every 15s to signal the tab is still open.
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		lastPing.Store(time.Now().UnixNano())
		w.WriteHeader(http.StatusNoContent)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	shutdown := make(chan struct{}, 1)

	// Graceful shutdown helper
	stop := func() {
		select {
		case shutdown <- struct{}{}:
		default:
		}
	}

	// Signal handler (Ctrl+C / kill)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		stop()
	}()

	// Idle watchdog: shut down when browser tab has been closed for idleTimeout
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			age := time.Duration(time.Now().UnixNano() - lastPing.Load())
			if age > idleTimeout {
				fmt.Fprintf(os.Stderr, "\nBrowser disconnected — shutting down.\n")
				stop()
				return
			}
		}
	}()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			stop()
		}
	}()

	time.Sleep(300 * time.Millisecond)

	// Detach from the controlling terminal so closing it doesn't kill the server.
	// This creates a new session — the process is now independent of the shell.
	syscall.Setsid() //nolint:errcheck

	url := fmt.Sprintf("http://localhost:%d", port)
	fmt.Fprintf(os.Stderr, "\n✓ Scan complete! Dashboard at %s\n", url)
	fmt.Fprintf(os.Stderr, "  PID %d — safe to close this terminal.\n", os.Getpid())
	fmt.Fprintf(os.Stderr, "  Server stops automatically when you close the browser tab.\n\n")

	openBrowser(url)

	<-shutdown

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx) //nolint:errcheck

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
	_ = cmd.Start() // Start async — don't block waiting for browser to close
}
