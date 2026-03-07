package scanner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/linkvectorized/vectorscan/pkg/models"
	"github.com/linkvectorized/vectorscan/pkg/platform"
)

// Scanner orchestrates security checks
type Scanner struct {
	platform       string
	osMajorVersion int // parsed from sw_vers, e.g. 14, 15, 26
	report         *models.Report
	platform_util  platform.Platform
	progressChan   chan ProgressUpdate
}

// ProgressUpdate reports scan progress
type ProgressUpdate struct {
	CurrentCheck int
	TotalChecks  int
	CheckName    string
}

// New creates a new scanner for the current platform
func New() (*Scanner, error) {
	plat := runtime.GOOS

	var pu platform.Platform
	switch plat {
	case "darwin":
		pu = platform.NewMacOS()
	case "linux":
		pu = platform.NewLinux()
	default:
		return nil, fmt.Errorf("unsupported platform: %s (macOS and Linux supported)", plat)
	}

	hostname, _ := os.Hostname()

	s := &Scanner{
		platform:      plat,
		platform_util: pu,
		progressChan:  make(chan ProgressUpdate, 100),
		report: &models.Report{
			Hostname: hostname,
			Platform: plat,
			ScanDate: time.Now(),
			Findings: []models.Finding{},
		},
	}

	// Parse OS major version for version-gated checks
	if ver, err := pu.GetOSVersion(); err == nil {
		parts := strings.Split(ver, ".")
		if len(parts) > 0 {
			major, _ := strconv.Atoi(parts[0])
			s.osMajorVersion = major
		}
	}

	return s, nil
}

// systemSettings returns the correct system settings app name for the current OS version.
// macOS 13 Ventura+ renamed "System Preferences" to "System Settings".
func (s *Scanner) systemSettings() string {
	if s.osMajorVersion >= 13 {
		return "System Settings"
	}
	return "System Preferences"
}

// ProgressChan returns the progress update channel
func (s *Scanner) ProgressChan() <-chan ProgressUpdate {
	return s.progressChan
}

// Scan runs all security checks
func (s *Scanner) Scan(ctx context.Context) (*models.Report, error) {
	startTime := time.Now()

	// Get OS version
	osVersion, _ := s.platform_util.GetOSVersion()
	s.report.OSVersion = osVersion

	// Run checks with a cancellable context to prevent goroutine leaks on timeout
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	findings := make(chan models.Finding, 100)

	go func() {
		defer close(findings)
		defer close(s.progressChan)

		checkNum := 0
		// 23 cross-platform base checks
		// darwin: +39 macOS-specific = 62 total
		// linux:  +7  Linux-specific = 30 total
		totalChecks := 23
		switch s.platform {
		case "darwin":
			totalChecks += 39
		case "linux":
			totalChecks += 7
		}

		// Helper to report progress (respects context cancellation)
		reportProgress := func(name string) {
			checkNum++
			select {
			case s.progressChan <- ProgressUpdate{checkNum, totalChecks, name}:
			case <-scanCtx.Done():
				return
			}
		}

		// Helper to run check with timeout
		runCheckWithTimeout := func(checkName string, checkFunc func(context.Context) (*models.Finding, error), timeout time.Duration) *models.Finding {
			result := make(chan *models.Finding, 1)
			go func() {
				if f, err := checkFunc(scanCtx); err == nil && f != nil {
					result <- f
				} else {
					result <- nil
				}
			}()

			select {
			case f := <-result:
				return f
			case <-time.After(timeout):
				// Timeout - return a finding indicating the check timed out
				return &models.Finding{
					ID:          "TIMEOUT-" + checkName,
					Category:    "system",
					Severity:    models.SeverityInfo,
					Title:       "Check timed out: " + checkName,
					Description: "This security check took too long to complete and was skipped to prevent scan hang.",
					Remediation: "The check may require elevated privileges or system resources. Try running again or manually verify this setting.",
					Evidence:    []string{"Check did not complete within timeout period"},
					Skipped:     true,
					Timestamp:   time.Now(),
				}
			}
		}

		// ── Cross-platform base checks (23) ─────────────────────────────────

		// Permissions
		reportProgress("Sudoers configuration")
		if f, err := s.checkSudoersConfig(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("World-writable files")
		if f, err := s.checkWorldWritable(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("SUID files")
		if f, err := s.checkSUIDFiles(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// Network
		reportProgress("Open ports")
		if f, err := s.checkOpenPorts(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// SSH
		reportProgress("SSH configuration")
		if f, err := s.checkSSHConfig(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("SSH key permissions")
		if f, err := s.checkSSHKeyPermissions(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("SSH strict host key checking")
		if f, err := s.checkSSHStrictHostKeyChecking(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Root SSH login")
		if f, err := s.checkRootSSHLogin(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("SSH key algorithms")
		if f, err := s.checkSSHKeyAlgorithms(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Weak ciphers")
		if f, err := s.checkWeakCiphers(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// Privilege escalation
		reportProgress("PATH hijacking")
		if f, err := s.checkPATHHijacking(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Writable system binaries")
		if f, err := s.checkWritableSystemBinaries(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// Files & credentials
		reportProgress("Shell config permissions")
		if f, err := s.checkShellConfigPermissions(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Credentials in home directory")
		if f, err := s.checkCredentialsInHome(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Git configuration security")
		if f, err := s.checkGitConfigSecurity(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// Authentication
		reportProgress("Empty password accounts")
		if f, err := s.checkEmptyPasswordAccounts(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Password expiration")
		if f, err := s.checkPasswordExpiration(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Account lockout")
		if f, err := s.checkAccountLockout(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// Kernel & system
		reportProgress("Core dumps")
		if f, err := s.checkCoreDumps(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// Logging
		reportProgress("Audit logging")
		if f, err := s.checkAuditLogging(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Syslog forwarding")
		if f, err := s.checkSyslogForwarding(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("DNSSEC validation")
		if f, err := s.checkDNSSECValidation(scanCtx); err == nil && f != nil {
			findings <- *f
		}
		reportProgress("Time synchronization")
		if f, err := s.checkTimeSync(scanCtx); err == nil && f != nil {
			findings <- *f
		}

		// ── macOS-specific checks (39) ────────────────────────────────────
		if s.platform == "darwin" {
			// System integrity
			reportProgress("System Integrity Protection")
			if f, err := s.checkSIP(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Gatekeeper")
			if f, err := s.checkGatekeeper(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("XProtect")
			if f, err := s.checkXProtectStatus(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Notarization")
			if f, err := s.checkNotarization(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Secure boot (T2)")
			if f, err := s.checkSecureBootT2(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Firmware updates")
			if f := runCheckWithTimeout("Firmware updates", s.checkFirmwareUpdates, 5*time.Second); f != nil {
				findings <- *f
			}
			reportProgress("System updates")
			if f := runCheckWithTimeout("System updates", s.checkSystemUpdates, 3*time.Second); f != nil {
				findings <- *f
			}

			// Encryption & auth
			reportProgress("FileVault status")
			if f, err := s.checkFileVaultStatus(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Password policy")
			if f, err := s.checkPasswordPolicy(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Touch ID for sudo")
			if f, err := s.checkTouchIDForSudo(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Login window security")
			if f, err := s.checkLoginWindowSecurity(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Guest account")
			if f, err := s.checkGuestAccountEnabled(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Automatic login")
			if f, err := s.checkAutomaticLoginEnabled(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Screen lock timeout")
			if f, err := s.checkScreenLockTimeout(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Sleep idle timeout")
			if f, err := s.checkSleepIdleTimeout(scanCtx); err == nil && f != nil {
				findings <- *f
			}

			// Network
			reportProgress("Firewall")
			if f, err := s.checkFirewall(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("SSH service status")
			if f, err := s.checkSSHServiceStatus(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("VPN status")
			if f, err := s.checkVPNStatus(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("DNS over HTTPS")
			if f, err := s.checkDNSOverHTTPS(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Bonjour/mDNS")
			if f, err := s.checkBonjourMDNS(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Bluetooth discoverability")
			if f, err := s.checkBluetoothDiscoverability(scanCtx); err == nil && f != nil {
				findings <- *f
			}

			// Privacy & access
			reportProgress("Microphone and camera access")
			if f := runCheckWithTimeout("Microphone and camera access", s.checkMicrophoneCamera, 5*time.Second); f != nil {
				findings <- *f
			}
			reportProgress("Accessibility permissions")
			if f, err := s.checkAccessibilityPermissions(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Location services")
			if f, err := s.checkLocationServices(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("iCloud Keychain")
			if f, err := s.checkiCloudKeychain(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Apple ID 2FA")
			if f, err := s.checkAppleID2FA(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("WiFi password storage")
			if f, err := s.checkWiFiPasswordStorage(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Browser security")
			if f, err := s.checkBrowserSecurity(scanCtx); err == nil && f != nil {
				findings <- *f
			}

			// Telemetry
			reportProgress("Spotlight telemetry")
			if f := runCheckWithTimeout("Spotlight telemetry", s.checkSpotlightTelemetry, 3*time.Second); f != nil {
				findings <- *f
			}
			reportProgress("Siri analytics")
			if f := runCheckWithTimeout("Siri analytics", s.checkSiriAnalytics, 3*time.Second); f != nil {
				findings <- *f
			}
			reportProgress("Apple analytics")
			if f := runCheckWithTimeout("Apple analytics", s.checkAppleAnalytics, 3*time.Second); f != nil {
				findings <- *f
			}
			reportProgress("Third-party data sharing")
			if f := runCheckWithTimeout("Third-party data sharing", s.checkThirdPartyDataSharing, 3*time.Second); f != nil {
				findings <- *f
			}

			// Kernel & persistence
			reportProgress("Kernel extensions")
			if f, err := s.checkKernelExtensions(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Kernel panic auto-reboot")
			if f, err := s.checkKernelPanicAutoReboot(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Launch agents permissions")
			if f, err := s.checkLaunchAgentsPermissions(scanCtx); err == nil && f != nil {
				findings <- *f
			}

			// Logging
			reportProgress("System log retention")
			if f, err := s.checkSystemLogRetention(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Crash reporter")
			if f, err := s.checkCrashReporter(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Spotlight indexing")
			if f, err := s.checkSpotlightIndexing(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("App Store unknown sources")
			if f, err := s.checkAppStoreUnknownSources(scanCtx); err == nil && f != nil {
				findings <- *f
			}
		}

		// ── Linux-specific checks (7) ─────────────────────────────────────
		if s.platform == "linux" {
			reportProgress("Firewall")
			if f, err := s.checkFirewallLinux(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Mandatory access control")
			if f, err := s.checkAppArmorSELinux(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Disk encryption (LUKS)")
			if f, err := s.checkLUKSEncryption(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Automatic security updates")
			if f, err := s.checkAutoUpdatesLinux(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("SSH service status")
			if f, err := s.checkSSHServiceLinux(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Kernel hardening")
			if f, err := s.checkKernelHardeningLinux(scanCtx); err == nil && f != nil {
				findings <- *f
			}
			reportProgress("Password policy (PAM)")
			if f, err := s.checkPasswordPolicyLinux(scanCtx); err == nil && f != nil {
				findings <- *f
			}
		}
	}()

	// Collect findings until channel closes (with timeout protection)
	done := false
	for !done {
		select {
		case f, ok := <-findings:
			if !ok {
				done = true
			} else {
				s.report.Findings = append(s.report.Findings, f)
			}
		case <-time.After(15 * time.Second):
			// Timeout: cancel scan context to unblock the goroutine
			scanCancel()
			fmt.Fprintf(os.Stderr, "\nWarning: Scan timeout, closing early with collected findings\n")
			done = true
		}
	}

	s.report.ScanTime = time.Since(startTime)
	s.report.Summarize()
	return s.report, nil
}

// Report returns the current report
func (s *Scanner) Report() *models.Report {
	return s.report
}
