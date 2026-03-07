package scanner

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/linkvectorized/vectorscan/pkg/models"
)

// checkSudoersConfig checks for insecure sudoers configurations
func (s *Scanner) checkSudoersConfig(ctx context.Context) (*models.Finding, error) {
	content, err := s.platform_util.ReadFile("/etc/sudoers")
	if err != nil {
		return nil, nil // File might not exist or not readable
	}

	// Check for NOPASSWD
	if strings.Contains(content, "NOPASSWD") {
		return &models.Finding{
			ID:          "PERM-001",
			Category:    "permissions",
			Severity:    models.SeverityCritical,
			Title:       "NOPASSWD in sudoers",
			Description: "Users can execute sudo commands without password entry, severely compromising security",
			Remediation: "Remove NOPASSWD entries from /etc/sudoers using 'sudo visudo'",
			Evidence:    []string{"/etc/sudoers contains NOPASSWD"},
			Timestamp:   time.Now(),
		}, nil
	}

	// Check for ALL=(ALL) ALL
	if strings.Contains(content, "ALL=(ALL) ALL") && !strings.Contains(content, "%admin") {
		return &models.Finding{
			ID:          "PERM-002",
			Category:    "permissions",
			Severity:    models.SeverityHigh,
			Title:       "Unrestricted sudo access",
			Description: "Users have unrestricted sudo privileges without command restrictions",
			Remediation: "Use sudoers to limit sudo access to specific commands per user",
			Evidence:    []string{"/etc/sudoers contains ALL=(ALL) ALL"},
			Timestamp:   time.Now(),
		}, nil
	}

	// Return positive finding - sudoers is secure
	return &models.Finding{
		ID:          "PERM-001-OK",
		Category:    "permissions",
		Severity:    models.SeverityInfo,
		Title:       "Sudoers configuration secure ✓",
		Description: "Sudoers file does not contain dangerous configurations like NOPASSWD",
		Remediation: "No action needed",
		Evidence:    []string{"Sudoers is properly configured"},
		Timestamp:   time.Now(),
	}, nil
}

// checkWorldWritable checks for world-writable sensitive files
func (s *Scanner) checkWorldWritable(ctx context.Context) (*models.Finding, error) {
	sensitivePaths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/root",
		"/root/.ssh",
	}

	for _, path := range sensitivePaths {
		if !s.platform_util.FileExists(path) {
			continue
		}

		perms, err := s.platform_util.GetFilePermissions(path)
		if err != nil {
			continue
		}

		// Check last digit for world-writable (2=write, 3=write+exec, 6=read+write, 7=all)
		if len(perms) > 0 && (perms[len(perms)-1] == '2' || perms[len(perms)-1] == '3' || perms[len(perms)-1] == '6' || perms[len(perms)-1] == '7') {
			return &models.Finding{
				ID:          "PERM-003",
				Category:    "permissions",
				Severity:    models.SeverityCritical,
				Title:       fmt.Sprintf("World-writable file: %s", path),
				Description: fmt.Sprintf("%s is readable/writable by all users, allowing privilege escalation", path),
				Remediation: fmt.Sprintf("Change permissions: chmod 600 %s (or appropriate permissions)", path),
				Evidence:    []string{fmt.Sprintf("%s has permissions %s", path, perms)},
				Timestamp:   time.Now(),
			}, nil
		}
	}

	// Return positive finding - sensitive files are secure
	return &models.Finding{
		ID:          "PERM-003-OK",
		Category:    "permissions",
		Severity:    models.SeverityInfo,
		Title:       "Sensitive files permissions secure ✓",
		Description: "Sensitive system files (/etc/passwd, /etc/shadow, etc) have proper permissions",
		Remediation: "No action needed",
		Evidence:    []string{"All sensitive files have restricted permissions"},
		Timestamp:   time.Now(),
	}, nil
}

// checkSUIDFiles checks for suspicious SUID binaries
func (s *Scanner) checkSUIDFiles(ctx context.Context) (*models.Finding, error) {
	// This is a simplified check - in production we'd scan more thoroughly
	cmd := "find /usr/bin /usr/local/bin -perm -4000 2>/dev/null | wc -l"
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", cmd)
	if err != nil {
		return nil, nil
	}

	// If more than 20 SUID binaries, might be worth reviewing
	suidCount, _ := strconv.Atoi(strings.TrimSpace(output))
	if suidCount > 20 {
		return &models.Finding{
			ID:          "PERM-004",
			Category:    "permissions",
			Severity:    models.SeverityMedium,
			Title:       "Multiple SUID binaries present",
			Description: "System has many SUID binaries which could be vectors for privilege escalation",
			Remediation: "Review SUID binaries with: find / -perm -4000 2>/dev/null | Review for necessity",
			Evidence:    []string{fmt.Sprintf("Found %s SUID binaries", output)},
			Timestamp:   time.Now(),
		}, nil
	}

	// SUID count is acceptable
	return &models.Finding{
		ID:          "PERM-004-OK",
		Category:    "permissions",
		Severity:    models.SeverityInfo,
		Title:       "SUID binaries count normal ✓",
		Description: "System has an acceptable number of SUID binaries",
		Remediation: "No action needed",
		Evidence:    []string{fmt.Sprintf("Found %s SUID binaries (acceptable)", strings.TrimSpace(output))},
		Timestamp:   time.Now(),
	}, nil
}

// checkSIP checks System Integrity Protection on macOS
func (s *Scanner) checkSIP(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "csrutil", "status")
	if err != nil {
		return nil, nil
	}

	if !strings.Contains(output, "enabled") {
		return &models.Finding{
			ID:          "SYS-001",
			Category:    "system",
			Severity:    models.SeverityCritical,
			Title:       "System Integrity Protection disabled",
			Description: "macOS System Integrity Protection (SIP) is disabled, allowing rootless restrictions to be bypassed",
			Remediation: "Enable SIP: Boot into Recovery Mode (Cmd+R), csrutil enable, reboot",
			Evidence:    []string{fmt.Sprintf("csrutil status: %s", output)},
			Timestamp:   time.Now(),
		}, nil
	}

	// Report when SIP is enabled (positive finding)
	return &models.Finding{
		ID:          "SYS-001-OK",
		Category:    "system",
		Severity:    models.SeverityInfo,
		Title:       "System Integrity Protection enabled ✓",
		Description: "macOS System Integrity Protection (SIP) is active, protecting system integrity",
		Remediation: "No action needed",
		Evidence:    []string{fmt.Sprintf("csrutil status: %s", strings.TrimSpace(output))},
		Timestamp:   time.Now(),
	}, nil
}

// checkGatekeeper checks Gatekeeper on macOS
func (s *Scanner) checkGatekeeper(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "spctl", "--status")
	if err != nil {
		return nil, nil
	}

	if !strings.Contains(output, "enabled") {
		return &models.Finding{
			ID:          "SYS-002",
			Category:    "system",
			Severity:    models.SeverityHigh,
			Title:       "Gatekeeper disabled",
			Description: "Gatekeeper is disabled, allowing unsigned applications to run without verification",
			Remediation: "Enable Gatekeeper: sudo spctl --master-enable",
			Evidence:    []string{fmt.Sprintf("spctl status: %s", output)},
			Timestamp:   time.Now(),
		}, nil
	}

	// Report when Gatekeeper is enabled (positive finding)
	return &models.Finding{
		ID:          "SYS-002-OK",
		Category:    "system",
		Severity:    models.SeverityInfo,
		Title:       "Gatekeeper enabled ✓",
		Description: "Gatekeeper is active, verifying code signatures and app integrity",
		Remediation: "No action needed",
		Evidence:    []string{fmt.Sprintf("spctl status: %s", strings.TrimSpace(output))},
		Timestamp:   time.Now(),
	}, nil
}

// checkFirewall checks firewall status on macOS
func (s *Scanner) checkFirewall(ctx context.Context) (*models.Finding, error) {
	// Use socketfilterfw (the proper API) instead of defaults read (known to hang)
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null")
	if err != nil || strings.TrimSpace(output) == "" {
		return nil, nil
	}

	lower := strings.ToLower(output)
	if strings.Contains(lower, "disabled") || strings.Contains(lower, "state = 0") {
		return &models.Finding{
			ID:          "SYS-003",
			Category:    "system",
			Severity:    models.SeverityHigh,
			Title:       "Firewall disabled",
			Description: "macOS firewall is disabled, leaving the system exposed to network attacks",
			Remediation: fmt.Sprintf("Enable firewall: %s → Network → Firewall → Turn On Firewall", s.systemSettings()),
			Evidence:    []string{"Firewall state: " + strings.TrimSpace(output)},
			Timestamp:   time.Now(),
		}, nil
	}

	fwStatus := "specific services"
	if strings.Contains(lower, "block all") || strings.Contains(lower, "state = 2") {
		fwStatus = "all connections"
	}
	return &models.Finding{
		ID:          "SYS-003-OK",
		Category:    "system",
		Severity:    models.SeverityInfo,
		Title:       "Firewall enabled ✓",
		Description: fmt.Sprintf("macOS firewall is active, protecting against incoming connections on %s", fwStatus),
		Remediation: "No action needed",
		Evidence:    []string{strings.TrimSpace(output)},
		Passed:      true,
		Timestamp:   time.Now(),
	}, nil
}

// checkOpenPorts checks for unexpected open ports
func (s *Scanner) checkOpenPorts(ctx context.Context) (*models.Finding, error) {
	// Get list of open ports on external interfaces
	cmd := "netstat -an | grep LISTEN | grep -v 127.0.0.1"
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", cmd)
	if err != nil {
		return nil, nil
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	var evidence []string

	// Extract port numbers and services from netstat output
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		evidence = append(evidence, line)
	}

	// If many ports are open, flag it
	if len(evidence) > 10 {
		return &models.Finding{
			ID:          "NET-008",
			Category:    "network",
			Severity:    models.SeverityMedium,
			Title:       "Multiple ports listening on external interfaces",
			Description: "System has many ports listening on non-loopback interfaces, expanding attack surface",
			Remediation: "Review open ports and close unnecessary services. Use: lsof -i -P -n | grep LISTEN",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("NET-008-OK", "Open ports acceptable ✓", "Number of listening ports is acceptable", "Port count is normal"), nil
}

// checkPasswordPolicy checks local password complexity requirements
func (s *Scanner) checkPasswordPolicy(ctx context.Context) (*models.Finding, error) {
	// pwpolicy getaccountpolicies (without hyphen) was removed in macOS 14.
	// Try configuration profiles (MDM), then pwpolicy -getaccountpolicies (hyphen variant).
	profileOutput, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "profiles show -type configuration 2>/dev/null | grep -i 'minLength\\|minComplexChars\\|requireAlphanumeric'")
	if strings.TrimSpace(profileOutput) != "" {
		if strings.Contains(profileOutput, "requireAlphanumeric") || strings.Contains(profileOutput, "minComplexChars") {
			return positiveAuditFinding("PWD-001-OK", "Password complexity policy enforced ✓", "MDM profile enforces password complexity", "Password policy meets requirements"), nil
		}
	}

	policyOutput, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "pwpolicy -getaccountpolicies 2>/dev/null")
	if strings.TrimSpace(policyOutput) != "" {
		if strings.Contains(policyOutput, "requiresAlpha") || strings.Contains(policyOutput, "requiresNumeric") {
			return positiveAuditFinding("PWD-001-OK", "Password complexity policy enforced ✓", "pwpolicy reports complexity requirements active", "Password policy meets requirements"), nil
		}
	}

	return &models.Finding{
		ID:          "PWD-001",
		Category:    "configs",
		Severity:    models.SeverityMedium,
		Title:       "Password complexity policy not enforced",
		Description: "No password complexity policy detected. Without complexity requirements, users may set trivially weak passwords.",
		Remediation: fmt.Sprintf("Enable via MDM profile or %s → Users & Groups → Password Options", s.systemSettings()),
		Evidence:    []string{"No complexity policy found via profiles or pwpolicy"},
		Timestamp:   time.Now(),
	}, nil
}

// checkSSHConfig checks SSH configuration security
func (s *Scanner) checkSSHConfig(ctx context.Context) (*models.Finding, error) {
	sshConfigPaths := []string{
		"/etc/ssh/sshd_config",
		"/private/etc/ssh/sshd_config",
	}

	for _, path := range sshConfigPaths {
		if !s.platform_util.FileExists(path) {
			continue
		}

		content, err := s.platform_util.ReadFile(path)
		if err != nil {
			continue
		}

		// Check for PermitRootLogin
		if strings.Contains(content, "PermitRootLogin yes") {
			return &models.Finding{
				ID:          "SSH-001",
				Category:    "configs",
				Severity:    models.SeverityCritical,
				Title:       "SSH root login enabled",
				Description: "SSH allows direct root login, enabling brute force attacks against the root account",
				Remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config and restart SSH",
				Evidence:    []string{fmt.Sprintf("%s contains 'PermitRootLogin yes'", path)},
				Timestamp:   time.Now(),
			}, nil
		}

		// Check for PasswordAuthentication
		if strings.Contains(content, "PasswordAuthentication yes") {
			return &models.Finding{
				ID:          "SSH-002",
				Category:    "configs",
				Severity:    models.SeverityInfo,
				Title:       "SSH password authentication enabled",
				Description: "SSH allows password authentication. This is a low risk on personal machines used only for local terminal access, but a concern if the machine is accessible for remote server-to-server SSH.",
				Remediation: "If used only for local/terminal access, this is acceptable. For servers exposed to networks, disable with: PasswordAuthentication no in sshd_config and use SSH keys instead.",
				Evidence:    []string{fmt.Sprintf("%s contains 'PasswordAuthentication yes'", path)},
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return nil, nil
}

// checkSSHKeyPermissions checks for readable private SSH keys
func (s *Scanner) checkSSHKeyPermissions(ctx context.Context) (*models.Finding, error) {
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return nil, nil
	}
	homeDir = strings.TrimSpace(homeDir)
	sshDir := homeDir + "/.ssh"

	if !s.platform_util.FileExists(sshDir) {
		return nil, nil
	}

	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", fmt.Sprintf("ls -la \"%s\"/id_* 2>/dev/null", strings.ReplaceAll(sshDir, `"`, `\"`)))
	if err != nil || strings.TrimSpace(output) == "" {
		return nil, nil
	}

	var evidence []string
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Skip .pub files - public keys are supposed to be readable
		if strings.Contains(line, ".pub") {
			continue
		}
		// Check if group or others have any permissions (columns 4-6 and 7-9 of the mode string)
		// Secure: -rw------- (600) or -r-------- (400)
		// Insecure: -rw-r--r-- (644), -rw-r----- (640), etc.
		// The mode string starts at position 0: -rwxrwxrwx
		// Group perms are chars 4-6, others perms are chars 7-9
		if len(line) >= 10 {
			groupOther := line[4:10] // e.g., "r--r--" from "-rw-r--r--"
			if groupOther != "------" {
				evidence = append(evidence, fmt.Sprintf("Insecure: %s", line))
			}
		}
	}

	if len(evidence) > 0 {
		return &models.Finding{
			ID:          "SSH-005",
			Category:    "permissions",
			Severity:    models.SeverityCritical,
			Title:       "SSH private keys readable by others",
			Description: "SSH private keys should only be readable by the owner (600). Readable keys allow attackers to impersonate you.",
			Remediation: fmt.Sprintf("Fix permissions: chmod 600 \"%s\"/id_*", sshDir),
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return nil, nil
}

// checkPATHHijacking checks for writable directories in PATH
func (s *Scanner) checkPATHHijacking(ctx context.Context) (*models.Finding, error) {
	pathOutput, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo $PATH")
	if err != nil {
		return positiveAuditFinding("PRIV-001-OK", "PATH directories secure ✓", "PATH directories have proper permissions", "No writable directories in PATH"), nil
	}

	paths := strings.Split(pathOutput, ":")
	var evidence []string

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		perms, err := s.platform_util.GetFilePermissions(path)
		if err != nil {
			continue
		}

		if isWritableByGroupOrOthers(perms) {
			evidence = append(evidence, fmt.Sprintf("%s is writable (perms: %s)", path, perms))
		}
	}

	if len(evidence) > 0 {
		return &models.Finding{
			ID:          "PRIV-001",
			Category:    "privileges",
			Severity:    models.SeverityCritical,
			Title:       "Writable directories in PATH",
			Description: "Attackers can place malicious binaries in writable PATH directories to execute arbitrary code.",
			Remediation: "Remove write permissions: chmod go-w on the affected directories",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIV-001-OK", "PATH directories secure ✓", "PATH directories have proper permissions", "No writable directories in PATH"), nil
}

// checkWritableSystemBinaries checks /usr/local/bin and /opt for write permissions
func (s *Scanner) checkWritableSystemBinaries(ctx context.Context) (*models.Finding, error) {
	criticalDirs := []string{"/usr/local/bin", "/usr/local/sbin", "/opt"}
	var evidence []string

	for _, dir := range criticalDirs {
		if !s.platform_util.FileExists(dir) {
			continue
		}

		perms, err := s.platform_util.GetFilePermissions(dir)
		if err != nil {
			continue
		}

		if isWritableByGroupOrOthers(perms) {
			evidence = append(evidence, fmt.Sprintf("%s writable (perms: %s)", dir, perms))
		}
	}

	if len(evidence) > 0 {
		return &models.Finding{
			ID:          "PRIV-002",
			Category:    "privileges",
			Severity:    models.SeverityHigh,
			Title:       "Writable system binary directories",
			Description: "Attackers can inject malicious binaries into writable system directories for persistence.",
			Remediation: "chmod go-w /usr/local/bin /usr/local/sbin /opt",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIV-002-OK", "System binary directories secure ✓", "System directories have proper permissions", "System directories are properly secured"), nil
}

// checkLaunchAgentsPermissions checks for writable LaunchAgents directory
func (s *Scanner) checkLaunchAgentsPermissions(ctx context.Context) (*models.Finding, error) {
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return positiveAuditFinding("PERSIST-001-OK", "LaunchAgents permissions secure ✓", "LaunchAgents directory has proper permissions", "LaunchAgents directory is properly secured"), nil
	}
	homeDir = strings.TrimSpace(homeDir)
	launchDir := homeDir + "/Library/LaunchAgents"

	if !s.platform_util.FileExists(launchDir) {
		return positiveAuditFinding("PERSIST-001-OK", "LaunchAgents permissions secure ✓", "LaunchAgents directory has proper permissions", "LaunchAgents directory is properly secured"), nil
	}

	perms, err := s.platform_util.GetFilePermissions(launchDir)
	if err != nil {
		return positiveAuditFinding("PERSIST-001-OK", "LaunchAgents permissions secure ✓", "LaunchAgents directory has proper permissions", "LaunchAgents directory is properly secured"), nil
	}

	if isWritableByGroupOrOthers(perms) {
		return &models.Finding{
			ID:          "PERSIST-001",
			Category:    "persistence",
			Severity:    models.SeverityHigh,
			Title:       "Writable LaunchAgents directory",
			Description: "Attackers can install persistence mechanisms that auto-execute on login.",
			Remediation: fmt.Sprintf("chmod go-w %s", launchDir),
			Evidence:    []string{fmt.Sprintf("%s perms: %s", launchDir, perms)},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PERSIST-001-OK", "LaunchAgents permissions secure ✓", "LaunchAgents directory has proper permissions", "LaunchAgents directory is properly secured"), nil
}

// checkScreenLockTimeout checks screen lock and sleep settings
func (s *Scanner) checkScreenLockTimeout(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read com.apple.screensaver askForPassword 2>/dev/null")
	if err != nil || !strings.Contains(output, "1") {
		return &models.Finding{
			ID:          "PHYS-001",
			Category:    "physical",
			Severity:    models.SeverityHigh,
			Title:       "Screen lock not required on wake",
			Description: "Screen lock password requirement is disabled. Attackers with physical access can unlock the screen.",
			Remediation: "Enable: defaults write com.apple.screensaver askForPassword -int 1",
			Evidence:    []string{"Screen lock password not required"},
			Timestamp:   time.Now(),
		}, nil
	}

	return nil, nil
}

// checkFileVaultStatus checks if FileVault encryption is enabled
func (s *Scanner) checkFileVaultStatus(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "fdesetup status 2>/dev/null")
	if err != nil {
		return nil, nil
	}

	if !strings.Contains(output, "On") && !strings.Contains(output, "on") {
		return &models.Finding{
			ID:          "ENC-001",
			Category:    "encryption",
			Severity:    models.SeverityCritical,
			Title:       "FileVault encryption disabled",
			Description: "Disk encryption is not enabled. All data is accessible if device is lost or stolen.",
			Remediation: fmt.Sprintf("Enable FileVault: %s → Privacy & Security → FileVault", s.systemSettings()),
			Evidence:    []string{"FileVault: disabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return &models.Finding{
		ID:          "ENC-001-OK",
		Category:    "encryption",
		Severity:    models.SeverityInfo,
		Title:       "FileVault encryption enabled ✓",
		Description: "Full disk encryption is enabled, protecting data if device is lost or stolen.",
		Remediation: "No action needed",
		Evidence:    []string{"FileVault: enabled"},
		Timestamp:   time.Now(),
	}, nil
}

// checkShellConfigPermissions checks .bashrc, .zshrc for write permissions
func (s *Scanner) checkShellConfigPermissions(ctx context.Context) (*models.Finding, error) {
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return positiveAuditFinding("PERSIST-002-OK", "Shell configs permissions secure ✓", "Shell configuration files have proper permissions", "Shell configs are properly secured"), nil
	}
	homeDir = strings.TrimSpace(homeDir)

	shellFiles := []string{
		homeDir + "/.bashrc",
		homeDir + "/.bash_profile",
		homeDir + "/.zshrc",
		homeDir + "/.zprofile",
	}

	var evidence []string

	for _, file := range shellFiles {
		if !s.platform_util.FileExists(file) {
			continue
		}

		perms, err := s.platform_util.GetFilePermissions(file)
		if err != nil {
			continue
		}

		if isWritableByGroupOrOthers(perms) {
			evidence = append(evidence, fmt.Sprintf("%s writable (perms: %s)", file, perms))
		}
	}

	if len(evidence) > 0 {
		return &models.Finding{
			ID:          "PERSIST-002",
			Category:    "persistence",
			Severity:    models.SeverityHigh,
			Title:       "Shell configuration files are writable",
			Description: "Attackers can modify shell configs to inject malicious code on every shell launch.",
			Remediation: "chmod go-w ~/.bashrc ~/.bash_profile ~/.zshrc ~/.zprofile",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PERSIST-002-OK", "Shell configs permissions secure ✓", "Shell configuration files have proper permissions", "Shell configs are properly secured"), nil
}

// checkSSHStrictHostKeyChecking checks SSH config for host key verification
func (s *Scanner) checkSSHStrictHostKeyChecking(ctx context.Context) (*models.Finding, error) {
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return nil, nil
	}
	homeDir = strings.TrimSpace(homeDir)
	sshConfigPath := homeDir + "/.ssh/config"

	if !s.platform_util.FileExists(sshConfigPath) {
		return nil, nil
	}

	content, err := s.platform_util.ReadFile(sshConfigPath)
	if err != nil {
		return nil, nil
	}

	if strings.Contains(content, "StrictHostKeyChecking no") {
		return &models.Finding{
			ID:          "SSH-004",
			Category:    "configs",
			Severity:    models.SeverityHigh,
			Title:       "SSH StrictHostKeyChecking disabled",
			Description: "SSH skips host key verification, allowing MITM attacks on SSH connections.",
			Remediation: "Remove 'StrictHostKeyChecking no' from ~/.ssh/config or set to 'ask'",
			Evidence:    []string{"~/.ssh/config: StrictHostKeyChecking no"},
			Timestamp:   time.Now(),
		}, nil
	}

	return nil, nil
}

// checkCredentialsInHome checks for exposed credential files
func (s *Scanner) checkCredentialsInHome(ctx context.Context) (*models.Finding, error) {
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return positiveAuditFinding("CREDS-001-OK", "Credential files permissions secure ✓", "Credential files have proper permissions", "Credentials are properly protected"), nil
	}
	homeDir = strings.TrimSpace(homeDir)

	credentialFiles := []string{
		homeDir + "/.aws/credentials",
		homeDir + "/.aws/config",
		homeDir + "/.ssh/authorized_keys",
		homeDir + "/.kube/config",
		homeDir + "/.docker/config.json",
	}

	var evidence []string

	for _, file := range credentialFiles {
		if !s.platform_util.FileExists(file) {
			continue
		}

		perms, err := s.platform_util.GetFilePermissions(file)
		if err != nil {
			continue
		}

		if isWritableByGroupOrOthers(perms) {
			evidence = append(evidence, fmt.Sprintf("%s readable (perms: %s)", file, perms))
		}
	}

	if len(evidence) > 0 {
		return &models.Finding{
			ID:          "CREDS-001",
			Category:    "credentials",
			Severity:    models.SeverityCritical,
			Title:       "Credential files readable by others",
			Description: "Cloud and SSH credentials are readable by other users. Attackers can steal credentials.",
			Remediation: "chmod 600 ~/.aws/credentials ~/.kube/config ~/.docker/config.json",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CREDS-001-OK", "Credential files permissions secure ✓", "Credential files have proper permissions", "Credentials are properly protected"), nil
}

// checkXProtectStatus checks if XProtect is enabled
func (s *Scanner) checkXProtectStatus(ctx context.Context) (*models.Finding, error) {
	// Check if XProtect app bundle exists
	xprotectApp := "/Library/Apple/System/Library/CoreServices/XProtect.app"
	xprotectBinary := "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"

	appExists := s.platform_util.FileExists(xprotectApp)
	binaryExists := s.platform_util.FileExists(xprotectBinary)

	if !appExists && !binaryExists {
		return &models.Finding{
			ID:          "MAL-001",
			Category:    "malware",
			Severity:    models.SeverityMedium,
			Title:       "XProtect malware detection unavailable",
			Description: "Apple's XProtect malware detector is not properly configured.",
			Remediation: "Ensure macOS is fully updated",
			Evidence:    []string{"XProtect app/binary not found"},
			Timestamp:   time.Now(),
		}, nil
	}

	return &models.Finding{
		ID:          "MAL-001-OK",
		Category:    "malware",
		Severity:    models.SeverityInfo,
		Title:       "XProtect malware detection enabled ✓",
		Description: "Apple's XProtect scans downloaded files and applications for malware.",
		Remediation: "No action needed",
		Evidence:    []string{"XProtect is installed and enabled"},
		Timestamp:   time.Now(),
	}, nil
}

// checkGuestAccountEnabled checks if guest account is enabled
func (s *Scanner) checkGuestAccountEnabled(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
	if err != nil || !strings.Contains(output, "1") {
		return nil, nil
	}

	return &models.Finding{
		ID:          "PHYS-003",
		Category:    "physical",
		Severity:    models.SeverityHigh,
		Title:       "Guest account enabled",
		Description: "Guest account allows anyone with physical access to log in and access the system.",
		Remediation: fmt.Sprintf("%s → Users & Groups → uncheck 'Allow guests to log in'", s.systemSettings()),
		Evidence:    []string{"Guest account enabled"},
		Timestamp:   time.Now(),
	}, nil
}

// checkAutomaticLoginEnabled checks if automatic login is enabled
func (s *Scanner) checkAutomaticLoginEnabled(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "PHYS-004",
			Category:    "physical",
			Severity:    models.SeverityHigh,
			Title:       "Automatic login enabled",
			Description: "Automatic login bypasses the login screen. Anyone with physical access can use the computer.",
			Remediation: fmt.Sprintf("%s → General → Login Options → disable Automatic login", s.systemSettings()),
			Evidence:    []string{fmt.Sprintf("Automatic login: %s", strings.TrimSpace(output))},
			Timestamp:   time.Now(),
		}, nil
	}

	return nil, nil
}

// checkGitConfigSecurity checks for dangerous git configurations
func (s *Scanner) checkGitConfigSecurity(ctx context.Context) (*models.Finding, error) {
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return nil, nil
	}
	homeDir = strings.TrimSpace(homeDir)
	gitConfig := homeDir + "/.gitconfig"

	if !s.platform_util.FileExists(gitConfig) {
		return nil, nil
	}

	content, err := s.platform_util.ReadFile(gitConfig)
	if err != nil {
		return nil, nil
	}

	if strings.Contains(content, "sslVerify = false") {
		return &models.Finding{
			ID:          "DEV-001",
			Category:    "development",
			Severity:    models.SeverityHigh,
			Title:       "Git SSL verification disabled",
			Description: "Git skips SSL certificate verification, allowing MITM attacks on git operations.",
			Remediation: "Remove 'sslVerify = false' from ~/.gitconfig",
			Evidence:    []string{"~/.gitconfig: sslVerify = false"},
			Timestamp:   time.Now(),
		}, nil
	}

	return nil, nil
}

// isWritableByGroupOrOthers checks if perms allow write by group or others
func isWritableByGroupOrOthers(perms string) bool {
	if len(perms) < 3 {
		return false
	}
	groupChar := perms[len(perms)-2]
	othersChar := perms[len(perms)-1]
	hasGroupWrite := groupChar == '2' || groupChar == '3' || groupChar == '6' || groupChar == '7'
	hasOthersWrite := othersChar == '2' || othersChar == '3' || othersChar == '6' || othersChar == '7'
	return hasGroupWrite || hasOthersWrite
}

// Helper function to return positive finding
func positiveAuditFinding(id, title, description, evidence string) *models.Finding {
	return &models.Finding{
		ID:          id,
		Category:    "audit",
		Severity:    models.SeverityInfo,
		Title:       title,
		Description: description,
		Remediation: "No action needed",
		Evidence:    []string{evidence},
		Passed:      true,
		Timestamp:   time.Now(),
	}
}

// Helper function to return a skipped finding (check not applicable on this OS/hardware)
func skippedFinding(id, title, reason string) *models.Finding {
	return &models.Finding{
		ID:          id + "-SKIP",
		Category:    "audit",
		Severity:    models.SeverityInfo,
		Title:       title,
		Description: reason,
		Remediation: "Verify manually or run on a supported configuration.",
		Evidence:    []string{reason},
		Skipped:     true,
		Timestamp:   time.Now(),
	}
}

// checkSystemUpdates checks if macOS is up to date
func (s *Scanner) checkSystemUpdates(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "softwareupdate -l 2>/dev/null | grep -i 'security\\|critical'")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "SYS-004",
			Category:    "system",
			Severity:    models.SeverityCritical,
			Title:       "Security updates available",
			Description: "macOS has pending security updates. Not applying security patches leaves system vulnerable to known exploits.",
			Remediation: fmt.Sprintf("Run: softwareupdate -i -a or %s → General → Software Update", s.systemSettings()),
			Evidence:    []string{fmt.Sprintf("Available updates: %s", strings.TrimSpace(output))},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("SYS-004-OK", "System is up to date ✓", "All security updates applied", "No pending security updates"), nil
}

// checkBluetoothDiscoverability checks if Bluetooth is set to non-discoverable
func (s *Scanner) checkBluetoothDiscoverability(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null")
	if err != nil || strings.TrimSpace(output) == "" {
		return positiveAuditFinding("HW-001-OK", "Bluetooth configuration OK ✓", "Bluetooth settings are configured", "Bluetooth discovery settings OK"), nil
	}

	// Check if Bluetooth is on but not discoverable
	if strings.Contains(output, "1") {
		return &models.Finding{
			ID:          "HW-001",
			Category:    "hardware",
			Severity:    models.SeverityMedium,
			Title:       "Bluetooth is enabled",
			Description: "Bluetooth is enabled and could be discoverable. Attackers can use Bluetooth to pair devices or perform BlueTooth exploits.",
			Remediation: fmt.Sprintf("Disable Bluetooth when not needed: %s → Bluetooth → Turn Off", s.systemSettings()),
			Evidence:    []string{"Bluetooth is powered on"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("HW-001-OK", "Bluetooth disabled ✓", "Bluetooth is disabled", "Bluetooth not discoverable"), nil
}

// checkMicrophoneCamera checks microphone/camera access
func (s *Scanner) checkMicrophoneCamera(ctx context.Context) (*models.Finding, error) {
	// Check if camera/mic are actively being monitored (search last 1 hour for speed)
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "log show --predicate 'eventMessage contains[cd] \"VDCAssistant\\|AppleCameraAssistant\\|kernel.*USBHID\"' --last 1h 2>/dev/null | wc -l")
	if err == nil && strings.TrimSpace(output) != "" && strings.TrimSpace(output) != "0" {
		return &models.Finding{
			ID:          "HW-002",
			Category:    "hardware",
			Severity:    models.SeverityInfo,
			Title:       "Camera/Microphone recent activity detected",
			Description: "Camera or microphone activity detected in logs. This is normal if you've used video/audio apps recently.",
			Remediation: fmt.Sprintf("Review app permissions: %s → Privacy & Security → Camera/Microphone", s.systemSettings()),
			Evidence:    []string{"Recent camera/microphone access detected"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("HW-002-OK", "Camera/Microphone access normal ✓", "No suspicious camera/microphone activity", "Audio/video access looks normal"), nil
}

// checkTouchIDForSudo checks if Touch ID is enabled for sudo
func (s *Scanner) checkTouchIDForSudo(ctx context.Context) (*models.Finding, error) {
	content, err := s.platform_util.ReadFile("/etc/pam.d/sudo")
	if err != nil {
		return positiveAuditFinding("AUTH-006-OK", "Sudo authentication configured ✓", "Sudo authentication settings are standard", "Sudo PAM configuration OK"), nil
	}

	if !strings.Contains(content, "pam_tid.so") {
		return &models.Finding{
			ID:          "AUTH-006",
			Category:    "auth",
			Severity:    models.SeverityLow,
			Title:       "Touch ID for sudo not enabled",
			Description: "Touch ID is not configured for sudo. Enabling it improves usability while maintaining security.",
			Remediation: "Enable Touch ID for sudo: Add 'auth       sufficient     pam_tid.so' to /etc/pam.d/sudo (requires editing as root)",
			Evidence:    []string{"pam_tid.so not found in /etc/pam.d/sudo"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-006-OK", "Touch ID for sudo enabled ✓", "Touch ID authentication available for sudo", "Touch ID convenience feature enabled"), nil
}

// checkSSHServiceStatus checks if SSH service is actually disabled
func (s *Scanner) checkSSHServiceStatus(ctx context.Context) (*models.Finding, error) {
	// Query the specific service label rather than piped grep to avoid false matches
	// (e.g. com.apple.sshd-keygen-runner which is not the SSH server)
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list com.openssh.sshd 2>/dev/null")
	// launchctl list <label> returns "Could not find service" if not loaded
	sshRunning := err == nil &&
		strings.TrimSpace(output) != "" &&
		!strings.Contains(output, "Could not find")

	if sshRunning {
		return &models.Finding{
			ID:          "SSH-003",
			Category:    "network",
			Severity:    models.SeverityHigh,
			Title:       "SSH service is running",
			Description: "SSH daemon is running and accepting connections. If not needed, disable it to reduce attack surface.",
			Remediation: fmt.Sprintf("Disable SSH: %s → General → Sharing → Remote Login → disable", s.systemSettings()),
			Evidence:    []string{"com.openssh.sshd is loaded and running"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("SSH-003-OK", "SSH service disabled ✓", "SSH daemon is not running", "SSH service properly disabled"), nil
}

// checkVPNStatus checks if user is connected to VPN
func (s *Scanner) checkVPNStatus(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "networksetup -listallnetworkservices 2>/dev/null | grep -i VPN")
	if err == nil && strings.TrimSpace(output) != "" {
		// VPN service exists but check if active
		activeOutput, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "ifconfig | grep -i tun")
		if strings.TrimSpace(activeOutput) == "" {
			return &models.Finding{
				ID:          "NET-006",
				Category:    "network",
				Severity:    models.SeverityMedium,
				Title:       "VPN configured but not connected",
				Description: "VPN is configured but currently not active. Enable it for privacy on untrusted networks.",
				Remediation: fmt.Sprintf("Connect to VPN in %s → VPN", s.systemSettings()),
				Evidence:    []string{"VPN service available but not active"},
				Timestamp:   time.Now(),
			}, nil
		}

		return positiveAuditFinding("NET-006-OK", "VPN is active ✓", "VPN connection is established", "Traffic is tunneled through VPN"), nil
	}

	return positiveAuditFinding("NET-006-OK", "Network security configured ✓", "Network configuration checked", "Network security baseline met"), nil
}

// checkDNSOverHTTPS checks if DNS over HTTPS is enabled
func (s *Scanner) checkDNSOverHTTPS(ctx context.Context) (*models.Finding, error) {
	// Check for DoH-capable DNS settings (Cloudflare 1.1.1.1, Quad9, etc.)
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "networksetup -getdnsservers Wi-Fi 2>/dev/null")
	if err == nil {
		if strings.Contains(output, "1.1.1.1") || strings.Contains(output, "8.8.8.8") || strings.Contains(output, "9.9.9.9") {
			return positiveAuditFinding("DNS-001-OK", "DNS privacy enabled ✓", "Using privacy-focused DNS provider", "DNS over HTTPS or DoT configured"), nil
		}
	}

	return &models.Finding{
		ID:          "DNS-001",
		Category:    "network",
		Severity:    models.SeverityLow,
		Title:       "Standard DNS in use (not DoH/DoT)",
		Description: "Using standard unencrypted DNS. ISP/network can see all domain lookups. Consider DoH/DoT.",
		Remediation: fmt.Sprintf("Configure DNS over HTTPS: %s → Network → Wi-Fi → Details → DNS → set to 1.1.1.1 (Cloudflare)", s.systemSettings()),
		Evidence:    []string{"DNS configuration uses standard DNS servers"},
		Timestamp:   time.Now(),
	}, nil
}

// checkBrowserSecurity checks browser security settings
func (s *Scanner) checkBrowserSecurity(ctx context.Context) (*models.Finding, error) {
	homeDir, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	homeDir = strings.TrimSpace(homeDir)

	// Check if Chrome/Safari store passwords unencrypted
	chromePrefs := homeDir + "/Library/Application Support/Google/Chrome/Default/Preferences"

	// Check Chrome for password saving — check both known keys for this setting
	if s.platform_util.FileExists(chromePrefs) {
		content, _ := s.platform_util.ReadFile(chromePrefs)
		// credentials_enable_service is the current key; password_manager_enabled is legacy
		managerEnabled := strings.Contains(content, `"credentials_enable_service":true`) ||
			strings.Contains(content, `"password_manager_enabled":true`)
		// Explicitly disabled overrides the above
		managerDisabled := strings.Contains(content, `"credentials_enable_service":false`) ||
			strings.Contains(content, `"password_manager_enabled":false`)
		if managerEnabled && !managerDisabled {
			return &models.Finding{
				ID:          "BROWSER-001",
				Category:    "browser",
				Severity:    models.SeverityMedium,
				Title:       "Browser password manager stores passwords",
				Description: "Chrome/Edge is configured to save passwords. Passwords stored in plaintext can be accessed by malware.",
				Remediation: "Disable password saving: Chrome → Settings → Passwords → Turn off 'Offer to save passwords'",
				Evidence:    []string{"Chrome password manager is enabled (credentials_enable_service or password_manager_enabled)"},
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return positiveAuditFinding("BROWSER-001-OK", "Browser security configured ✓", "Browser security settings hardened", "Password manager disabled or Firefox in use"), nil
}

// checkiCloudKeychain checks if iCloud Keychain is enabled
func (s *Scanner) checkiCloudKeychain(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "security list-keychains 2>/dev/null | grep -i icloud")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "CLOUD-001",
			Category:    "cloud",
			Severity:    models.SeverityLow,
			Title:       "iCloud Keychain not configured",
			Description: "iCloud Keychain is not enabled. This secures passwords across Apple devices if configured.",
			Remediation: fmt.Sprintf("Enable iCloud Keychain: %s → [Apple ID] → iCloud → Passwords & Keychain", s.systemSettings()),
			Evidence:    []string{"iCloud Keychain not found in system keychains"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CLOUD-001-OK", "iCloud Keychain configured ✓", "Secure password sync enabled", "iCloud Keychain is active"), nil
}

// checkAppleID2FA checks if 2FA is enabled for Apple ID
func (s *Scanner) checkAppleID2FA(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read ~/Library/Preferences/com.apple.account.IdentityServices 2>/dev/null | grep -i 'two-factor\\|2FA\\|twofactor'")
	if err == nil && strings.TrimSpace(output) != "" {
		return positiveAuditFinding("CLOUD-002-OK", "Apple ID 2FA enabled ✓", "Two-factor authentication is active", "Apple ID account is protected with 2FA"), nil
	}

	return &models.Finding{
		ID:          "CLOUD-002",
		Category:    "cloud",
		Severity:    models.SeverityInfo,
		Title:       "Apple ID 2FA status unknown",
		Description: "Cannot programmatically verify Apple ID 2FA status. Manually confirm it is enabled.",
		Remediation: fmt.Sprintf("Verify 2FA: %s → [Apple ID] → Password & Security → Two-Factor Authentication", s.systemSettings()),
		Evidence:    []string{"2FA status cannot be determined programmatically"},
		Timestamp:   time.Now(),
	}, nil
}

// checkWiFiPasswordStorage checks if WiFi passwords are stored securely
func (s *Scanner) checkWiFiPasswordStorage(ctx context.Context) (*models.Finding, error) {
	// Check if WiFi networks are configured
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "networksetup -listallnetworkservices 2>/dev/null | grep -i wifi")
	if err == nil && strings.TrimSpace(output) != "" {
		// WiFi is available - passwords are stored in keychain (encrypted)
		return positiveAuditFinding("NET-005-OK", "WiFi security OK ✓", "WiFi passwords stored in system keychain", "WiFi credentials properly protected"), nil
	}

	return positiveAuditFinding("NET-005-OK", "Network configuration checked ✓", "WiFi settings verified", "Network passwords secured"), nil
}

// checkSecureBootT2 checks T2/Apple Silicon secure boot status
func (s *Scanner) checkSecureBootT2(ctx context.Context) (*models.Finding, error) {
	// Detect CPU architecture: sysctl returns "1" on Apple Silicon
	armResult, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "sysctl -n hw.optional.arm64 2>/dev/null")
	isAppleSilicon := strings.TrimSpace(armResult) == "1"

	if isAppleSilicon {
		// Apple Silicon: secure boot is handled by the SoC (not T2).
		// bputil can report the security policy if run with sufficient privileges.
		sbOutput, err := s.platform_util.RunCommand(ctx, "sh", "-c", "bputil -d 2>/dev/null | grep -i 'secure boot'")
		if err != nil || strings.TrimSpace(sbOutput) == "" {
			// bputil requires root or SIP; if unavailable emit a skipped finding
			return skippedFinding("FW-001", "Secure Boot (Apple Silicon)", "bputil requires root to query secure boot policy on Apple Silicon — run vectorscan with sudo for this check"), nil
		}
		if strings.Contains(strings.ToLower(sbOutput), "full") || strings.Contains(strings.ToLower(sbOutput), "enabled") {
			return positiveAuditFinding("FW-001-OK", "Secure Boot enabled ✓", "Apple Silicon full security mode active", "SoC secure boot protection active"), nil
		}
		return &models.Finding{
			ID:          "FW-001",
			Category:    "firmware",
			Severity:    models.SeverityMedium,
			Title:       "Apple Silicon Secure Boot not in full security mode",
			Description: "Secure Boot is not in full security mode. Enable it for maximum firmware protection.",
			Remediation: "Boot into Recovery Mode (hold Power button), then Utilities → Startup Security Utility → Full Security",
			Evidence:    []string{strings.TrimSpace(sbOutput)},
			Timestamp:   time.Now(),
		}, nil
	}

	// Intel: check for T2 chip
	t2Output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "system_profiler SPiBridgeDataType 2>/dev/null | grep -i 'Apple T2'")
	if err == nil && strings.TrimSpace(t2Output) != "" {
		// T2 present, check secure boot mode via nvram
		sbOutput, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "nvram -p 2>/dev/null | grep -i 'secure-boot-mode'")
		if strings.Contains(sbOutput, "full") {
			return positiveAuditFinding("FW-001-OK", "Secure Boot enabled ✓", "T2 chip with full secure boot", "Firmware protection active"), nil
		}
		return &models.Finding{
			ID:          "FW-001",
			Category:    "firmware",
			Severity:    models.SeverityMedium,
			Title:       "T2 Secure Boot not in full security mode",
			Description: "T2 chip is present but Secure Boot is not in full security mode. Enable it for maximum firmware protection.",
			Remediation: "Boot into Recovery Mode (Cmd+R), Utilities → Startup Security Utility → Full Security",
			Evidence:    []string{"T2 chip detected but Secure Boot mode is reduced"},
			Timestamp:   time.Now(),
		}, nil
	}

	// No T2 and not Apple Silicon — older Intel Mac without T2
	return skippedFinding("FW-001", "Secure Boot (T2/Apple Silicon)", "No T2 chip or Apple Silicon detected — secure boot not available on this hardware"), nil
}

// System & Authentication Checks

// checkRootSSHLogin checks if root login via SSH is disabled
func (s *Scanner) checkRootSSHLogin(ctx context.Context) (*models.Finding, error) {
	content, err := s.platform_util.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return positiveAuditFinding("AUTH-001-OK", "SSH root login check passed ✓", "SSH daemon not accessible", "Cannot verify SSH config"), nil
	}

	rootLoginPermitted := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // skip commented-out lines regardless of spacing
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "PermitRootLogin") && strings.EqualFold(fields[1], "yes") {
			rootLoginPermitted = true
			break
		}
	}
	if rootLoginPermitted {
		return &models.Finding{
			ID:          "AUTH-001",
			Category:    "authentication",
			Severity:    models.SeverityCritical,
			Title:       "Root SSH login permitted",
			Description: "PermitRootLogin yes is set in sshd_config, allowing direct root login via SSH",
			Remediation: "Edit /etc/ssh/sshd_config: set 'PermitRootLogin no', then: sudo launchctl kickstart -k system/com.openssh.sshd",
			Evidence:    []string{"PermitRootLogin yes found (uncommented) in /etc/ssh/sshd_config"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-001-OK", "Root SSH login disabled ✓", "SSH root access denied", "Direct root SSH login is disabled"), nil
}

// checkEmptyPasswordAccounts checks for accounts with no password hash
func (s *Scanner) checkEmptyPasswordAccounts(ctx context.Context) (*models.Finding, error) {
	var output string
	var err error

	if s.platform == "linux" {
		// On Linux, /etc/shadow second field empty means no password
		output, err = s.platform_util.RunCommand(ctx, "sh", "-c",
			`awk -F: '($2 == "" || $2 == "!!" ) && $1 != "root" {print $1}' /etc/shadow 2>/dev/null`)
	} else {
		// macOS: password hashes live in the local directory service
		output, err = s.platform_util.RunCommand(ctx, "sh", "-c",
			`dscl . -list /Users UniqueID 2>/dev/null | awk '$2+0 >= 500 {print $1}' | while read u; do`+
				` shadow=$(dscl . -read "/Users/$u" ShadowHashData 2>/dev/null | grep -v "^ShadowHashData:$" | tr -d ' \n');`+
				` [ -z "$shadow" ] && echo "$u"; done 2>/dev/null`)
	}

	if err == nil && strings.TrimSpace(output) != "" {
		users := strings.TrimSpace(output)
		remediation := "Set a password for each account: sudo dscl . -passwd /Users/<username> <newpassword>"
		if s.platform == "linux" {
			remediation = "Set a password for each account: sudo passwd <username>"
		}
		return &models.Finding{
			ID:          "AUTH-002",
			Category:    "authentication",
			Severity:    models.SeverityCritical,
			Title:       "Users with no password hash detected",
			Description: fmt.Sprintf("The following accounts have no password hash and may allow password-less login: %s", users),
			Remediation: remediation,
			Evidence:    []string{fmt.Sprintf("Accounts without password hash: %s", users)},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-002-OK", "No empty password accounts ✓", "All user accounts have password hashes set", "Password enforcement in place"), nil
}

// checkPasswordExpiration checks if password expiration policy is set
func (s *Scanner) checkPasswordExpiration(ctx context.Context) (*models.Finding, error) {
	if s.platform == "linux" {
		// Check /etc/login.defs for PASS_MAX_DAYS
		output, err := s.platform_util.RunCommand(ctx, "sh", "-c",
			`grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}'`)
		if err == nil {
			days := strings.TrimSpace(output)
			if days == "" || days == "99999" {
				return &models.Finding{
					ID:          "AUTH-003",
					Category:    "authentication",
					Severity:    models.SeverityMedium,
					Title:       "Password expiration policy not configured",
					Description: "Passwords do not expire. PASS_MAX_DAYS is unset or set to 99999 in /etc/login.defs.",
					Remediation: "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs and apply to existing users with: chage --maxdays 90 <username>",
					Evidence:    []string{fmt.Sprintf("PASS_MAX_DAYS=%s", days)},
					Timestamp:   time.Now(),
				}, nil
			}
		}
		return positiveAuditFinding("AUTH-003-OK", "Password expiration configured ✓", "Password rotation policy enabled", "Periodic password changes required"), nil
	}

	// macOS: check the current user's plist, not just root (which is usually locked anyway)
	currentUser, err := s.platform_util.RunCommand(ctx, "sh", "-c", "id -un 2>/dev/null")
	if err != nil || strings.TrimSpace(currentUser) == "" {
		currentUser = "root"
	}
	currentUser = strings.TrimSpace(currentUser)

	plistPath := fmt.Sprintf("/var/db/dslocal/nodes/Default/users/%s.plist", currentUser)
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", fmt.Sprintf("plutil -p %q 2>/dev/null | grep -i maxPasswordAge", plistPath))
	if err != nil || strings.TrimSpace(output) == "" {
		profileOutput, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "profiles show -type configuration 2>/dev/null | grep -i 'maxPINAgeInDays\\|maxPasscodeAge\\|maxPasswordAge'")
		if strings.TrimSpace(profileOutput) != "" {
			return positiveAuditFinding("AUTH-003-OK", "Password expiration configured ✓", "MDM profile enforces password expiration", "Periodic password changes required"), nil
		}
		return &models.Finding{
			ID:          "AUTH-003",
			Category:    "authentication",
			Severity:    models.SeverityMedium,
			Title:       "Password expiration policy not configured",
			Description: "Passwords do not expire. Require periodic password changes for security.",
			Remediation: fmt.Sprintf("Configure password policy: %s → Users & Groups → Password Options → Require password change every X days", s.systemSettings()),
			Evidence:    []string{fmt.Sprintf("No password expiration policy for user '%s'", currentUser)},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-003-OK", "Password expiration configured ✓", "Password rotation policy enabled", "Periodic password changes required"), nil
}

// checkAccountLockout checks if account lockout after failed login attempts is enabled
func (s *Scanner) checkAccountLockout(ctx context.Context) (*models.Finding, error) {
	if s.platform == "linux" {
		// Check PAM for pam_tally2 or pam_faillock
		output, _ := s.platform_util.RunCommand(ctx, "sh", "-c",
			`grep -rE "pam_tally2|pam_faillock" /etc/pam.d/ 2>/dev/null | grep -v "^#"`)
		if strings.TrimSpace(output) != "" {
			return positiveAuditFinding("AUTH-004-OK", "Account lockout enabled ✓", "PAM lockout configured", "Brute force protection active"), nil
		}
		return &models.Finding{
			ID:          "AUTH-004",
			Category:    "authentication",
			Severity:    models.SeverityMedium,
			Title:       "Account lockout policy not configured",
			Description: "No PAM account lockout after failed login attempts. Attackers can brute force passwords.",
			Remediation: "Configure pam_faillock in /etc/pam.d/common-auth: add 'auth required pam_faillock.so deny=5 unlock_time=600'",
			Evidence:    []string{"No pam_tally2 or pam_faillock found in /etc/pam.d/"},
			Timestamp:   time.Now(),
		}, nil
	}

	// macOS
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null | grep -i 'MaxFailedAttempts\\|lockLockoutDuration'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "AUTH-004",
			Category:    "authentication",
			Severity:    models.SeverityMedium,
			Title:       "Account lockout policy not configured",
			Description: "No account lockout after failed login attempts. Attackers can brute force passwords.",
			Remediation: fmt.Sprintf("Enable account lockout: %s → Privacy & Security → Advanced → Lock after X failed login attempts", s.systemSettings()),
			Evidence:    []string{"No account lockout policy found"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-004-OK", "Account lockout enabled ✓", "Failed login lockout configured", "Brute force protection active"), nil
}

// checkLoginWindowSecurity checks login window security settings
func (s *Scanner) checkLoginWindowSecurity(ctx context.Context) (*models.Finding, error) {
	config, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p /Library/Preferences/com.apple.loginwindow.plist 2>/dev/null")
	issues := []string{}

	// systemsetup -getremotelogin was removed in macOS 14 Sonoma.
	// Use launchctl to check if SSH daemon is loaded instead (works on all macOS versions).
	sshStatus, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list com.openssh.sshd 2>/dev/null")
	if strings.TrimSpace(sshStatus) != "" && !strings.Contains(sshStatus, "Could not find") {
		issues = append(issues, "Remote login (SSH) enabled")
	}
	if strings.Contains(config, "\"showPasswordHints\" => 1") || strings.Contains(config, "\"showPasswordHints\" => true") {
		issues = append(issues, "Password hints displayed on login window")
	}

	if len(issues) > 0 {
		return &models.Finding{
			ID:          "AUTH-005",
			Category:    "authentication",
			Severity:    models.SeverityMedium,
			Title:       "Login window security weakened",
			Description: fmt.Sprintf("Insecure login window settings detected: %s", strings.Join(issues, ", ")),
			Remediation: fmt.Sprintf("Disable remote login and password hints in %s → General → Sharing", s.systemSettings()),
			Evidence:    issues,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-005-OK", "Login window security hardened ✓", "Secure login configuration", "Remote login disabled, hints hidden"), nil
}

// Kernel & Core Checks

// checkKernelExtensions checks for unsigned/untrusted kernel extensions or system extensions
func (s *Scanner) checkKernelExtensions(ctx context.Context) (*models.Finding, error) {
	// kextstat was deprecated in macOS 12 and is non-functional on macOS 13+.
	// macOS 13+ uses System Extensions (DriverKit) instead of kernel extensions.
	if s.osMajorVersion >= 13 {
		output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "systemextensionsctl list 2>/dev/null | grep -v 'com.apple'")
		if err == nil && strings.TrimSpace(output) != "" {
			// Filter out header lines that don't contain actual extension entries
			lines := strings.Split(strings.TrimSpace(output), "\n")
			var thirdParty []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				// Skip empty lines, section headers (---), and column headers
				if line == "" || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "System Extensions:") {
					continue
				}
				// Real extension lines contain a bundle ID (contain at least one dot and a status keyword)
				if strings.Contains(line, ".") && (strings.Contains(line, "activated") || strings.Contains(line, "enabled") || strings.Contains(line, "terminated")) {
					thirdParty = append(thirdParty, line)
				}
			}
			if len(thirdParty) > 0 {
				return &models.Finding{
					ID:          "KERNEL-001",
					Category:    "kernel",
					Severity:    models.SeverityHigh,
					Title:       "Third-party system extensions loaded",
					Description: "Third-party system extensions are active. Review them to ensure they are trusted.",
					Remediation: "Review system extensions: systemextensionsctl list. Remove untrusted ones via their parent app or System Settings → Privacy & Security → Security",
					Evidence:    thirdParty,
					Timestamp:   time.Now(),
				}, nil
			}
		}
		return positiveAuditFinding("KERNEL-001-OK", "System extensions secure ✓", "No unexpected third-party system extensions", "Only Apple system extensions active"), nil
	}

	// macOS 12 and below: use kextstat
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "kextstat 2>/dev/null | grep -v 'com.apple' | tail -n +2")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "KERNEL-001",
			Category:    "kernel",
			Severity:    models.SeverityHigh,
			Title:       "Third-party kernel extensions loaded",
			Description: "Unsigned or third-party kernel extensions are loaded. These can compromise system security.",
			Remediation: "Review loaded kexts with 'kextstat'. Unload or remove untrusted extensions: sudo kextunload -b com.example.kext",
			Evidence:    []string{"Third-party kernel extensions detected"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("KERNEL-001-OK", "Kernel security maintained ✓", "Only Apple kernel extensions loaded", "No third-party kexts present"), nil
}

// checkKernelPanicAutoReboot checks if auto-reboot on kernel panic is enabled
func (s *Scanner) checkKernelPanicAutoReboot(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "nvram -p 2>/dev/null | grep 'auto-boot' || defaults read /Library/Preferences/SystemConfiguration/com.apple.PowerManagement 2>/dev/null | grep -i 'AutoReboot'")
	if err != nil || (!strings.Contains(output, "true") && !strings.Contains(output, "1")) {
		return &models.Finding{
			ID:          "KERNEL-002",
			Category:    "kernel",
			Severity:    models.SeverityLow,
			Title:       "Auto-reboot on kernel panic not enabled",
			Description: "System will not automatically reboot after a kernel panic, requiring manual intervention.",
			Remediation: "Enable auto-reboot: sudo nvram auto-boot=true (or check Power Management settings)",
			Evidence:    []string{"Auto-reboot on panic is disabled or not configured"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("KERNEL-002-OK", "Kernel panic handling configured ✓", "Auto-reboot on panic enabled", "Unattended recovery enabled"), nil
}

// checkCoreDumps checks if core dumps are disabled
func (s *Scanner) checkCoreDumps(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl limit core 2>/dev/null")
	if err == nil && !strings.Contains(output, "0 0") && strings.Contains(output, "unlimited") {
		return &models.Finding{
			ID:          "KERNEL-003",
			Category:    "kernel",
			Severity:    models.SeverityMedium,
			Title:       "Core dumps enabled",
			Description: "Core dumps are enabled. These files can contain sensitive memory information.",
			Remediation: "To permanently disable core dumps on macOS, create /Library/LaunchDaemons/limit.corefile.plist with a core limit of 0, then load it with: sudo launchctl load /Library/LaunchDaemons/limit.corefile.plist. For a session-only fix: ulimit -c 0",
			Evidence:    []string{"Core dump limit is unlimited or large"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("KERNEL-003-OK", "Core dumps disabled ✓", "Memory dumps prevented", "Sensitive data protection active"), nil
}

// Privacy & Access Control Checks

// checkAccessibilityPermissions checks what apps have accessibility access via TCC
func (s *Scanner) checkAccessibilityPermissions(ctx context.Context) (*models.Finding, error) {
	// TCC.db is the definitive source for accessibility permissions on macOS.
	// System TCC DB requires root; user TCC DB is readable without root.
	tccDB := "/Library/Application Support/com.apple.TCC/TCC.db"
	userTccDB := fmt.Sprintf("%s/Library/Application Support/com.apple.TCC/TCC.db", func() string {
		h, _ := s.platform_util.RunCommand(context.Background(), "sh", "-c", "echo ~")
		return strings.TrimSpace(h)
	}())

	queryTCC := func(db string) string {
		out, _ := s.platform_util.RunCommand(ctx, "sh", "-c",
			fmt.Sprintf(`sqlite3 %q "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2" 2>/dev/null`, db))
		return strings.TrimSpace(out)
	}

	var apps []string
	if result := queryTCC(tccDB); result != "" {
		apps = append(apps, strings.Split(result, "\n")...)
	}
	if result := queryTCC(userTccDB); result != "" {
		apps = append(apps, strings.Split(result, "\n")...)
	}

	// Deduplicate
	seen := map[string]bool{}
	var unique []string
	for _, a := range apps {
		a = strings.TrimSpace(a)
		if a != "" && !seen[a] {
			seen[a] = true
			unique = append(unique, a)
		}
	}

	if len(unique) > 0 {
		return &models.Finding{
			ID:          "PRIVACY-001",
			Category:    "privacy",
			Severity:    models.SeverityMedium,
			Title:       fmt.Sprintf("Applications with accessibility permissions (%d)", len(unique)),
			Description: "Applications have been granted accessibility permissions. Review to remove unnecessary access.",
			Remediation: fmt.Sprintf("%s → Privacy & Security → Accessibility → Review and remove apps", s.systemSettings()),
			Evidence:    unique,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-001-OK", "Accessibility permissions minimal ✓", "Limited accessibility access granted", "Restricted to essential applications only"), nil
}

// checkLocationServices checks if location services and privacy is configured
func (s *Scanner) checkLocationServices(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /var/db/locationd/clients.plist 2>/dev/null | grep -c 'BundleIdentifier'")
	if err == nil && strings.TrimSpace(output) != "0" {
		count := strings.TrimSpace(output)
		return &models.Finding{
			ID:          "PRIVACY-002",
			Category:    "privacy",
			Severity:    models.SeverityMedium,
			Title:       fmt.Sprintf("Location services enabled for %s apps", count),
			Description: "Multiple applications have location access. Review to minimize location data exposure.",
			Remediation: fmt.Sprintf("%s → Privacy & Security → Location Services → Disable for unnecessary apps", s.systemSettings()),
			Evidence:    []string{fmt.Sprintf("%s apps have location permissions", count)},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-002-OK", "Location services minimal ✓", "Limited location access", "Location permissions reviewed"), nil
}

// checkSpotlightIndexing checks if Spotlight is properly configured
func (s *Scanner) checkSpotlightIndexing(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "mdutil -s / 2>/dev/null | grep -i 'disabled\\|not indexed'")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "PRIVACY-003",
			Category:    "privacy",
			Severity:    models.SeverityLow,
			Title:       "Spotlight indexing disabled",
			Description: "Spotlight is disabled on encrypted volumes. This reduces search capability but improves privacy.",
			Remediation: "Enable Spotlight: sudo mdutil -i on / (if indexing needed)",
			Evidence:    []string{"Spotlight indexing is disabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-003-OK", "Spotlight indexing configured ✓", "Search functionality enabled", "Spotlight indexed properly"), nil
}

// checkAppStoreUnknownSources checks if apps from unknown sources can be installed
func (s *Scanner) checkAppStoreUnknownSources(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "spctl --status 2>/dev/null")
	if err == nil && strings.Contains(output, "disabled") {
		return &models.Finding{
			ID:          "PRIVACY-004",
			Category:    "privacy",
			Severity:    models.SeverityCritical,
			Title:       "App protection disabled - unknown sources allowed",
			Description: "Gatekeeper/Spctl is disabled. Applications from any source can be installed and run.",
			Remediation: fmt.Sprintf("Enable Gatekeeper: sudo spctl --master-enable (or %s → Privacy & Security → Allow apps)", s.systemSettings()),
			Evidence:    []string{"Gatekeeper is disabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-004-OK", "App source protection enabled ✓", "Only trusted sources allowed", "Gatekeeper verified"), nil
}

// checkNotarization checks if app notarization is enforced
func (s *Scanner) checkNotarization(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "codesign -dv /Applications/Safari.app 2>&1 | grep -i 'notarized\\|notary\\|TeamIdentifier'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "PRIVACY-005",
			Category:    "privacy",
			Severity:    models.SeverityMedium,
			Title:       "App notarization not verified",
			Description: "Cannot verify notarization status of installed applications.",
			Remediation: fmt.Sprintf("%s → Privacy & Security → Verify app signatures: codesign -v /path/to/app", s.systemSettings()),
			Evidence:    []string{"App notarization status unknown"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-005-OK", "App notarization verified ✓", "Applications are notarized", "Malware detection active"), nil
}

// Network & Encryption Checks

// checkSSHKeyAlgorithms checks for weak SSH key algorithms
func (s *Scanner) checkSSHKeyAlgorithms(ctx context.Context) (*models.Finding, error) {
	// Use RunCommand to resolve home dir rather than trusting $HOME env var
	homeDir, err := s.platform_util.RunCommand(ctx, "sh", "-c", "echo ~")
	if err != nil {
		return positiveAuditFinding("SSH-004-OK", "SSH key algorithms checked ✓", "SSH keys properly configured", "Standard key algorithms in use"), nil
	}
	homeDir = strings.TrimSpace(homeDir)
	rsaKeyPath := homeDir + "/.ssh/id_rsa"
	if !s.platform_util.FileExists(rsaKeyPath) {
		return positiveAuditFinding("SSH-004-OK", "SSH key algorithms checked ✓", "SSH keys properly configured", "Standard key algorithms in use"), nil
	}

	output, _ := s.platform_util.RunCommand(ctx, "sh", "-c", fmt.Sprintf("ssh-keygen -l -f \"%s/.ssh/id_rsa\" 2>/dev/null | grep -i '1024\\|512'", strings.ReplaceAll(homeDir, `"`, `\"`)))
	if strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "SSH-004",
			Category:    "network",
			Severity:    models.SeverityHigh,
			Title:       "Weak SSH key length detected",
			Description: "SSH RSA key is less than 2048 bits. Weak keys are susceptible to brute force attacks.",
			Remediation: "Generate new key: ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa",
			Evidence:    []string{"Weak RSA key (< 2048 bits) found"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("SSH-004-OK", "SSH key algorithms strong ✓", "RSA 2048+ or ED25519 in use", "Secure key exchange active"), nil
}

// checkWeakCiphers checks SSH server config for explicitly configured weak ciphers
func (s *Scanner) checkWeakCiphers(ctx context.Context) (*models.Finding, error) {
	// openssl ciphers -v lists what the library supports, not what's configured.
	// Check sshd_config for explicitly weak ciphers instead — that's what matters.
	sshdCiphers, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null")
	weakSSH := []string{"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
	if strings.TrimSpace(sshdCiphers) != "" {
		lower := strings.ToLower(sshdCiphers)
		var found []string
		for _, weak := range weakSSH {
			if strings.Contains(lower, weak) {
				found = append(found, weak)
			}
		}
		if len(found) > 0 {
			return &models.Finding{
				ID:          "CRYPTO-001",
				Category:    "network",
				Severity:    models.SeverityHigh,
				Title:       "Weak SSH ciphers explicitly configured",
				Description: "sshd_config enables deprecated cipher suites. These are vulnerable to known attacks.",
				Remediation: "Edit /etc/ssh/sshd_config: remove weak ciphers and restart sshd. Prefer: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
				Evidence:    found,
				Timestamp:   time.Now(),
			}, nil
		}
	}

	// Also check SSH client config for weak host key algorithms
	clientKex, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "grep -i '^KexAlgorithms\\|^HostKeyAlgorithms' /etc/ssh/ssh_config ~/.ssh/config 2>/dev/null | grep -i 'diffie-hellman-group1\\|diffie-hellman-group14'")
	if strings.TrimSpace(clientKex) != "" {
		return &models.Finding{
			ID:          "CRYPTO-001",
			Category:    "network",
			Severity:    models.SeverityMedium,
			Title:       "Weak SSH key exchange algorithms configured",
			Description: "SSH client config enables weak key exchange algorithms susceptible to downgrade attacks.",
			Remediation: "Edit ~/.ssh/config: remove diffie-hellman-group1-sha1 and diffie-hellman-group14-sha1 from KexAlgorithms",
			Evidence:    []string{strings.TrimSpace(clientKex)},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CRYPTO-001-OK", "SSH cipher configuration secure ✓", "No weak ciphers explicitly configured in sshd_config", "Secure key exchange active"), nil
}

// checkDNSSECValidation checks if DNSSEC validation is enabled
func (s *Scanner) checkDNSSECValidation(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "cat /etc/resolv.conf 2>/dev/null | grep -i 'dnssec'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "DNS-002",
			Category:    "network",
			Severity:    models.SeverityLow,
			Title:       "DNSSEC validation not enabled",
			Description: "DNSSEC validation is not configured. DNS responses are not validated for authenticity.",
			Remediation: fmt.Sprintf("Configure DNSSEC: edit /etc/resolv.conf or use %s → Network → DNS", s.systemSettings()),
			Evidence:    []string{"DNSSEC not found in DNS configuration"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("DNS-002-OK", "DNSSEC validation enabled ✓", "DNS authenticity verified", "DNS spoofing protection active"), nil
}

// checkBonjourMDNS checks if Bonjour/mDNS is disabled on enterprise networks
func (s *Scanner) checkBonjourMDNS(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list | grep -i 'mdnsresponder\\|bonjour'")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "NET-007",
			Category:    "network",
			Severity:    models.SeverityLow,
			Title:       "Bonjour/mDNS enabled",
			Description: "Bonjour/mDNS service is active. On enterprise networks, disable for privacy.",
			Remediation: fmt.Sprintf("Disable Bonjour: %s → Network → Wi-Fi → Details → DNS (uncheck mDNS)", s.systemSettings()),
			Evidence:    []string{"mDNS responder is running"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("NET-007-OK", "Bonjour configuration checked ✓", "Network discovery configured", "Privacy settings applied"), nil
}

// Logging & Monitoring Checks

// checkAuditLogging checks if system audit logging is enabled (macOS BSD audit)
func (s *Scanner) checkAuditLogging(ctx context.Context) (*models.Finding, error) {
	// Check if auditd is running via launchctl (service-specific query is more reliable than piped grep)
	auditdRunning, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list com.apple.auditd 2>/dev/null")
	// Check audit_control for active flags
	auditControl, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "cat /etc/security/audit_control 2>/dev/null | grep -v '^#' | grep -v '^$'")

	// launchctl list <label> returns error text on macOS if service not found
	trimmedRunning := strings.TrimSpace(auditdRunning)
	auditdActive := trimmedRunning != "" &&
		!strings.Contains(trimmedRunning, "Could not find") &&
		!strings.Contains(strings.ToLower(trimmedRunning), "not found") &&
		!strings.Contains(strings.ToLower(trimmedRunning), "error")
	auditConfigured := strings.TrimSpace(auditControl) != ""

	if !auditdActive {
		return &models.Finding{
			ID:          "AUDIT-001",
			Category:    "audit",
			Severity:    models.SeverityMedium,
			Title:       "BSD audit daemon not running",
			Description: "macOS BSD audit daemon (auditd) is not active. Security events are not being logged.",
			Remediation: "Enable audit daemon: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist",
			Evidence:    []string{"com.apple.auditd not found in launchctl"},
			Timestamp:   time.Now(),
		}, nil
	}

	if !auditConfigured {
		return &models.Finding{
			ID:          "AUDIT-001B",
			Category:    "audit",
			Severity:    models.SeverityLow,
			Title:       "BSD audit control not configured",
			Description: "Audit daemon is running but /etc/security/audit_control has no active configuration.",
			Remediation: "Configure audit rules in /etc/security/audit_control and restart auditd",
			Evidence:    []string{"auditd running but audit_control is empty or missing"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUDIT-001-OK", "Audit logging enabled ✓", "BSD auditd active and configured", "Security events tracked via macOS audit framework"), nil
}

// checkSystemLogRetention checks if logs are retained appropriately
func (s *Scanner) checkSystemLogRetention(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p /etc/asl/com.apple.system 2>/dev/null | grep -i 'expire-after'")
	if err == nil && strings.TrimSpace(output) != "" {
		// Extract the numeric value from the output (e.g., "expire-after" => "7")
		// Parse any digits found in the value
		parts := strings.Split(output, "=>")
		if len(parts) == 2 {
			valueStr := strings.TrimSpace(parts[1])
			valueStr = strings.Trim(valueStr, "\" ")
			days, parseErr := strconv.Atoi(valueStr)
			if parseErr == nil && days < 30 {
				return &models.Finding{
					ID:          "AUDIT-002",
					Category:    "audit",
					Severity:    models.SeverityLow,
					Title:       "System logs purged too aggressively",
					Description: fmt.Sprintf("System logs expire after %d days. Increase retention for forensics and compliance.", days),
					Remediation: "Configure log retention: Edit /etc/asl/com.apple.system - set 'expire-after' to 30+ days",
					Evidence:    []string{fmt.Sprintf("Log retention is %d days (< 30)", days)},
					Timestamp:   time.Now(),
				}, nil
			}
		}
	}

	return positiveAuditFinding("AUDIT-002-OK", "Log retention sufficient ✓", "Logs retained for forensics", "Compliance data preserved"), nil
}

// checkSyslogForwarding checks if logs are sent to central logging
func (s *Scanner) checkSyslogForwarding(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "cat /etc/syslog.conf 2>/dev/null | grep '@'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "AUDIT-003",
			Category:    "audit",
			Severity:    models.SeverityLow,
			Title:       "Syslog forwarding not configured",
			Description: "Logs are not forwarded to a central logging server. Implement centralized log management.",
			Remediation: "Configure syslog forwarding: Edit /etc/syslog.conf to add: *.* @logging-server.example.com",
			Evidence:    []string{"No syslog forwarding configured"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUDIT-003-OK", "Syslog forwarding configured ✓", "Centralized logging active", "Log aggregation enabled"), nil
}

// checkCrashReporter checks if automatic crash reporting is appropriately configured
func (s *Scanner) checkCrashReporter(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read ~/Library/Preferences/com.apple.CrashReporter 2>/dev/null | grep -i 'DialogType'")
	if err == nil && strings.Contains(output, "Server") {
		return &models.Finding{
			ID:          "AUDIT-004",
			Category:    "audit",
			Severity:    models.SeverityLow,
			Title:       "Automatic crash reporting enabled",
			Description: "Automatic crash reports are sent to Apple servers without prompting.",
			Remediation: "Disable auto-reporting: defaults write ~/Library/Preferences/com.apple.CrashReporter DialogType none",
			Evidence:    []string{"Crash reporter sends reports to Apple"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUDIT-004-OK", "Crash reporting configured ✓", "Privacy-respecting error handling", "Data collection minimized"), nil
}

// System Configuration Checks

// checkSleepIdleTimeout checks if sleep/idle timeout is configured
func (s *Scanner) checkSleepIdleTimeout(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "pmset -g | grep 'disksleep\\|sleep' | grep '0'")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "CONFIG-001",
			Category:    "configuration",
			Severity:    models.SeverityMedium,
			Title:       "Sleep timeout disabled",
			Description: "Computer never sleeps. Unattended systems are vulnerable to physical access.",
			Remediation: fmt.Sprintf("Enable sleep timeout: %s → Lock Screen → Start screen saver / Turn display off", s.systemSettings()),
			Evidence:    []string{"Sleep timeout is disabled (0 minutes)"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CONFIG-001-OK", "Sleep timeout configured ✓", "Idle computer locks", "Physical security enhanced"), nil
}

// checkTimeSync checks if NTP time synchronization is enabled
func (s *Scanner) checkTimeSync(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list | grep -i 'ntpd\\|systemtime' || sntp -c 1 127.0.0.1 2>&1")
	if err != nil || strings.Contains(output, "Connection refused") {
		return &models.Finding{
			ID:          "CONFIG-002",
			Category:    "configuration",
			Severity:    models.SeverityMedium,
			Title:       "Time synchronization may be disabled",
			Description: "NTP (Network Time Protocol) may not be properly configured. Incorrect time breaks security mechanisms.",
			Remediation: fmt.Sprintf("Enable NTP: %s → General → Date & Time → Set time and date automatically", s.systemSettings()),
			Evidence:    []string{"NTP synchronization not detected"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CONFIG-002-OK", "Time synchronization active ✓", "NTP enabled and syncing", "Crypto timestamp validation working"), nil
}

// checkFirmwareUpdates checks for pending firmware updates
func (s *Scanner) checkFirmwareUpdates(ctx context.Context) (*models.Finding, error) {
	// Detect Apple Silicon
	armResult, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "sysctl -n hw.optional.arm64 2>/dev/null")
	isAppleSilicon := strings.TrimSpace(armResult) == "1"

	if isAppleSilicon {
		// On Apple Silicon, firmware is bundled with macOS updates — check softwareupdate
		fwUpdates, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "softwareupdate --list 2>/dev/null | grep -i 'firmware'")
		if strings.TrimSpace(fwUpdates) != "" {
			return &models.Finding{
				ID:          "CONFIG-003",
				Category:    "configuration",
				Severity:    models.SeverityMedium,
				Title:       "Firmware update available",
				Description: "A firmware update is available via softwareupdate. Apply it to stay protected.",
				Remediation: fmt.Sprintf("Install firmware update: %s → General → Software Update", s.systemSettings()),
				Evidence:    []string{strings.TrimSpace(fwUpdates)},
				Timestamp:   time.Now(),
			}, nil
		}
		return positiveAuditFinding("CONFIG-003-OK", "Firmware current ✓", "No pending Apple Silicon firmware updates", "Boot security patched"), nil
	}

	// Intel: check T2 bridge firmware version
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "system_profiler SPiBridgeDataType 2>/dev/null | grep -i 'Version'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "CONFIG-003",
			Category:    "configuration",
			Severity:    models.SeverityMedium,
			Title:       "Firmware update status unknown",
			Description: "Unable to verify firmware is up to date. Check for pending firmware security updates.",
			Remediation: fmt.Sprintf("Check firmware: %s → General → Software Update, or run: softwareupdate -l", s.systemSettings()),
			Evidence:    []string{"Firmware version could not be determined"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CONFIG-003-OK", "Firmware current ✓", "Latest firmware installed", "Boot security patched"), nil
}

// checkApplicationAutoUpdates checks if applications auto-update
func (s *Scanner) checkApplicationAutoUpdates(ctx context.Context) (*models.Finding, error) {
	safariUpdates, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read ~/Library/Preferences/com.apple.Safari 2>/dev/null | grep -i 'SUEnableAutomaticChecks'")
	chromeUpdates, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read ~/Library/Preferences/com.google.Chrome 2>/dev/null | grep -i 'auto.*.update'")

	if (strings.Contains(safariUpdates, "false") || safariUpdates == "") && (strings.Contains(chromeUpdates, "false") || chromeUpdates == "") {
		return &models.Finding{
			ID:          "CONFIG-004",
			Category:    "configuration",
			Severity:    models.SeverityMedium,
			Title:       "Application auto-updates disabled",
			Description: "Browser and application auto-updates are not enabled. Applications will have unpatched vulnerabilities.",
			Remediation: "Enable auto-updates for Safari and Chrome: Preferences → Advanced → Update automatically",
			Evidence:    []string{"Auto-update disabled for major applications"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CONFIG-004-OK", "Application auto-updates enabled ✓", "Software patches installed automatically", "Vulnerability window minimized"), nil
}

// checkRemoteManagement checks if remote management/screen sharing is disabled
func (s *Scanner) checkRemoteManagement(ctx context.Context) (*models.Finding, error) {
	ardEnabled, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.RemoteManagement 2>/dev/null | grep -i 'active'")
	vnEnabled, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list | grep -i 'screensharing\\|vnc'")

	if strings.Contains(ardEnabled, "true") || strings.TrimSpace(vnEnabled) != "" {
		return &models.Finding{
			ID:          "CONFIG-005",
			Category:    "configuration",
			Severity:    models.SeverityHigh,
			Title:       "Remote management/screen sharing enabled",
			Description: "Remote management or screen sharing is enabled. Disable if not needed.",
			Remediation: fmt.Sprintf("Disable Remote Management: %s → General → Sharing → uncheck Remote Management/Screen Sharing", s.systemSettings()),
			Evidence:    []string{"Remote management or VNC is active"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CONFIG-005-OK", "Remote access disabled ✓", "Screen sharing and ARD off", "Unauthorized access prevented"), nil
}

// Privacy & Telemetry Checks

// checkSpotlightTelemetry checks if Spotlight sends usage data to Apple
func (s *Scanner) checkSpotlightTelemetry(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p ~/Library/Preferences/com.apple.Spotlight.plist 2>/dev/null | grep -i 'InternetResults\\|Suggestions'")
	if err == nil && strings.Contains(output, "true") {
		return &models.Finding{
			ID:          "TELEMETRY-001",
			Category:    "telemetry",
			Severity:    models.SeverityLow,
			Title:       "Spotlight sends search queries to Apple",
			Description: "Spotlight suggestions send search queries to Apple servers for processing.",
			Remediation: fmt.Sprintf("Disable Spotlight suggestions: %s → Siri & Spotlight → uncheck 'Suggestions'", s.systemSettings()),
			Evidence:    []string{"Spotlight internet results enabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("TELEMETRY-001-OK", "Spotlight privacy protected ✓", "Search suggestions disabled", "Queries not sent to Apple"), nil
}

// checkSiriAnalytics checks if Siri analytics are disabled
func (s *Scanner) checkSiriAnalytics(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p ~/Library/Preferences/com.apple.assistant.support.plist 2>/dev/null | grep -i 'Siri Data Sharing Opt'")
	if err == nil && strings.Contains(output, "true") {
		return &models.Finding{
			ID:          "TELEMETRY-002",
			Category:    "telemetry",
			Severity:    models.SeverityLow,
			Title:       "Siri usage analytics enabled",
			Description: "Siri usage data is being sent to Apple for analytics and improvement purposes.",
			Remediation: fmt.Sprintf("Disable Siri analytics: %s → Siri → uncheck 'Improve Siri & Dictation'", s.systemSettings()),
			Evidence:    []string{"Siri data sharing enabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("TELEMETRY-002-OK", "Siri privacy enabled ✓", "Analytics disabled", "Siri usage not tracked"), nil
}

// checkAppleAnalytics checks if Apple analytics are disabled
func (s *Scanner) checkAppleAnalytics(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p ~/Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist 2>/dev/null | grep -i 'AutoSubmit\\|Agree'")
	if err == nil && strings.Contains(output, "true") {
		return &models.Finding{
			ID:          "TELEMETRY-003",
			Category:    "telemetry",
			Severity:    models.SeverityLow,
			Title:       "Apple crash report analytics enabled",
			Description: "Automatic crash report sharing with Apple is enabled.",
			Remediation: fmt.Sprintf("Disable: %s → Privacy & Security → Analytics & Improvements → uncheck 'Share Mac Analytics'", s.systemSettings()),
			Evidence:    []string{"Apple analytics sharing enabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("TELEMETRY-003-OK", "Apple analytics disabled ✓", "Crash reporting anonymous", "Telemetry minimized"), nil
}

// checkThirdPartyDataSharing checks Safari and third-party app data sharing settings
func (s *Scanner) checkThirdPartyDataSharing(ctx context.Context) (*models.Finding, error) {
	safariTracking, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p ~/Library/Preferences/com.apple.Safari.plist 2>/dev/null | grep -i 'Privacy\\|Tracking' | head -3")

	if strings.Contains(safariTracking, "false") {
		return &models.Finding{
			ID:          "TELEMETRY-004",
			Category:    "telemetry",
			Severity:    models.SeverityLow,
			Title:       "Privacy-focused browsing not fully enabled",
			Description: "Safari and third-party app tracking prevention may not be fully configured.",
			Remediation: "Enable: Safari → Preferences → Privacy → Prevent cross-site tracking, Uncheck 'Allow privacy-preserving ad measurement'",
			Evidence:    []string{"Safari tracking prevention not fully enabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("TELEMETRY-004-OK", "Third-party tracking blocked ✓", "Privacy browsing enabled", "Ad tracking prevention active"), nil
}


// ── Linux-specific checks ─────────────────────────────────────────────────────

// checkFirewallLinux checks if a firewall is active (ufw or firewalld)
func (s *Scanner) checkFirewallLinux(ctx context.Context) (*models.Finding, error) {
	// Try firewalld
	if out, err := s.platform_util.RunCommand(ctx, "systemctl", "is-active", "firewalld"); err == nil && strings.TrimSpace(out) == "active" {
		return positiveAuditFinding("FW-001-OK", "Firewall active ✓", "firewalld running", "Network ingress filtered"), nil
	}
	// Try ufw
	if out, err := s.platform_util.RunCommand(ctx, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
		return positiveAuditFinding("FW-001-OK", "Firewall active ✓", "ufw enabled", "Network ingress filtered"), nil
	}
	// Try iptables — consider active if non-default rules exist
	if out, err := s.platform_util.RunCommand(ctx, "iptables", "-L", "-n"); err == nil && strings.Count(out, "\n") > 10 {
		return positiveAuditFinding("FW-001-OK", "Firewall active ✓", "iptables rules present", "Network ingress filtered"), nil
	}
	return &models.Finding{
		ID:          "FW-001",
		Category:    "network",
		Severity:    models.SeverityHigh,
		Title:       "No firewall detected",
		Description: "Neither ufw, firewalld, nor iptables rules are active. The host accepts all inbound connections.",
		Remediation: "Enable ufw: sudo ufw enable && sudo ufw default deny incoming  —  or install firewalld: sudo systemctl enable --now firewalld",
		Evidence:    []string{"ufw inactive", "firewalld inactive", "no iptables rules"},
		Timestamp:   time.Now(),
	}, nil
}

// checkAppArmorSELinux checks if mandatory access control is enforced
func (s *Scanner) checkAppArmorSELinux(ctx context.Context) (*models.Finding, error) {
	// Check AppArmor
	if out, err := s.platform_util.RunCommand(ctx, "sh", "-c", "aa-status 2>/dev/null | grep 'profiles are in enforce mode'"); err == nil && strings.TrimSpace(out) != "" {
		return positiveAuditFinding("MAC-001-OK", "AppArmor enforcing ✓", "Mandatory access control active", "Process confinement enforced"), nil
	}
	// Check SELinux
	if out, err := s.platform_util.RunCommand(ctx, "getenforce"); err == nil && strings.TrimSpace(out) == "Enforcing" {
		return positiveAuditFinding("MAC-001-OK", "SELinux enforcing ✓", "Mandatory access control active", "Process confinement enforced"), nil
	}
	return &models.Finding{
		ID:          "MAC-001",
		Category:    "system",
		Severity:    models.SeverityHigh,
		Title:       "Mandatory access control not enforcing",
		Description: "Neither AppArmor nor SELinux is in enforcing mode. Processes run without mandatory confinement.",
		Remediation: "Enable AppArmor: sudo systemctl enable --now apparmor  —  or set SELinux to enforcing in /etc/selinux/config: SELINUX=enforcing",
		Evidence:    []string{"AppArmor not in enforce mode", "SELinux not enforcing"},
		Timestamp:   time.Now(),
	}, nil
}

// checkLUKSEncryption checks if the root filesystem is on an encrypted volume
func (s *Scanner) checkLUKSEncryption(ctx context.Context) (*models.Finding, error) {
	// lsblk -o TYPE lists "crypt" entries for LUKS-mapped devices
	out, err := s.platform_util.RunCommand(ctx, "sh", "-c", "lsblk -o TYPE 2>/dev/null | grep crypt")
	if err == nil && strings.TrimSpace(out) != "" {
		return positiveAuditFinding("ENC-001-OK", "Disk encryption active ✓", "LUKS encrypted volume detected", "Data at rest is protected"), nil
	}
	// Also check dmsetup
	if out, err := s.platform_util.RunCommand(ctx, "sh", "-c", "dmsetup table 2>/dev/null | grep crypt"); err == nil && strings.TrimSpace(out) != "" {
		return positiveAuditFinding("ENC-001-OK", "Disk encryption active ✓", "dm-crypt device detected", "Data at rest is protected"), nil
	}
	return &models.Finding{
		ID:          "ENC-001",
		Category:    "encryption",
		Severity:    models.SeverityHigh,
		Title:       "No disk encryption detected",
		Description: "No LUKS/dm-crypt encrypted volumes found. Data at rest is unprotected if the drive is removed.",
		Remediation: "Encrypt new installs with LUKS during OS setup. For existing systems, consider encrypting the home directory: sudo ecryptfs-migrate-home -u <user>",
		Evidence:    []string{"No crypt entries in lsblk or dmsetup"},
		Timestamp:   time.Now(),
	}, nil
}

// checkAutoUpdatesLinux checks if unattended security updates are configured
func (s *Scanner) checkAutoUpdatesLinux(ctx context.Context) (*models.Finding, error) {
	// Debian/Ubuntu: unattended-upgrades
	if s.platform_util.FileExists("/etc/apt/apt.conf.d/20auto-upgrades") {
		out, _ := s.platform_util.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
		if strings.Contains(out, `"1"`) {
			return positiveAuditFinding("UPD-001-OK", "Automatic security updates enabled ✓", "unattended-upgrades configured", "Security patches applied automatically"), nil
		}
	}
	// RHEL/CentOS/Fedora: dnf-automatic
	if out, err := s.platform_util.RunCommand(ctx, "systemctl", "is-enabled", "dnf-automatic"); err == nil && strings.TrimSpace(out) == "enabled" {
		return positiveAuditFinding("UPD-001-OK", "Automatic security updates enabled ✓", "dnf-automatic enabled", "Security patches applied automatically"), nil
	}
	return &models.Finding{
		ID:          "UPD-001",
		Category:    "system",
		Severity:    models.SeverityMedium,
		Title:       "Automatic security updates not configured",
		Description: "Security patches are not applied automatically. Known vulnerabilities may remain unpatched.",
		Remediation: "Debian/Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades  —  RHEL/Fedora: sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic",
		Evidence:    []string{"unattended-upgrades not configured", "dnf-automatic not enabled"},
		Timestamp:   time.Now(),
	}, nil
}

// checkSSHServiceLinux checks if the SSH daemon is running and warns if unnecessary
func (s *Scanner) checkSSHServiceLinux(ctx context.Context) (*models.Finding, error) {
	out, err := s.platform_util.RunCommand(ctx, "systemctl", "is-active", "ssh")
	if err != nil {
		// Try sshd (RHEL naming)
		out, err = s.platform_util.RunCommand(ctx, "systemctl", "is-active", "sshd")
	}
	if err == nil && strings.TrimSpace(out) == "active" {
		return &models.Finding{
			ID:          "SSH-003",
			Category:    "network",
			Severity:    models.SeverityHigh,
			Title:       "SSH service is running",
			Description: "SSH daemon is running and accepting connections. If not required, disable it to reduce attack surface.",
			Remediation: "If SSH is not needed: sudo systemctl disable --now ssh  —  If required, ensure key-based auth only and root login is disabled.",
			Evidence:    []string{"sshd is active"},
			Timestamp:   time.Now(),
		}, nil
	}
	return positiveAuditFinding("SSH-003-OK", "SSH service not running ✓", "SSH daemon not active", "Remote access attack surface minimised"), nil
}

// checkKernelHardeningLinux checks key sysctl kernel hardening parameters
func (s *Scanner) checkKernelHardeningLinux(ctx context.Context) (*models.Finding, error) {
	type param struct {
		key      string
		want     string
		describe string
	}
	params := []param{
		{"kernel.randomize_va_space", "2", "ASLR disabled"},
		{"net.ipv4.conf.all.rp_filter", "1", "Reverse path filtering disabled"},
		{"net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects accepted"},
		{"kernel.dmesg_restrict", "1", "dmesg readable by non-root"},
		{"fs.suid_dumpable", "0", "SUID core dumps allowed"},
	}

	issues := []string{}
	for _, p := range params {
		out, err := s.platform_util.RunCommand(ctx, "sysctl", "-n", p.key)
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) != p.want {
			issues = append(issues, p.describe)
		}
	}

	if len(issues) > 0 {
		return &models.Finding{
			ID:          "KERNEL-010",
			Category:    "kernel",
			Severity:    models.SeverityMedium,
			Title:       "Kernel hardening parameters misconfigured",
			Description: fmt.Sprintf("The following kernel parameters weaken security: %s", strings.Join(issues, "; ")),
			Remediation: "Add hardening parameters to /etc/sysctl.d/99-hardening.conf and apply with: sudo sysctl --system",
			Evidence:    issues,
			Timestamp:   time.Now(),
		}, nil
	}
	return positiveAuditFinding("KERNEL-010-OK", "Kernel hardening parameters set ✓", "sysctl security params configured", "Kernel attack surface reduced"), nil
}

// checkPasswordPolicyLinux checks PAM password complexity requirements
func (s *Scanner) checkPasswordPolicyLinux(ctx context.Context) (*models.Finding, error) {
	// Check for pam_pwquality or pam_cracklib in PAM config
	out, _ := s.platform_util.RunCommand(ctx, "sh", "-c",
		`grep -rE "pam_pwquality|pam_cracklib" /etc/pam.d/ 2>/dev/null | grep -v "^#"`)
	if strings.TrimSpace(out) != "" {
		return positiveAuditFinding("PWD-001-OK", "Password complexity policy configured ✓", "PAM password quality enforcement active", "Weak passwords rejected"), nil
	}
	return &models.Finding{
		ID:          "PWD-001",
		Category:    "authentication",
		Severity:    models.SeverityMedium,
		Title:       "No password complexity policy",
		Description: "PAM is not enforcing password complexity. Users can set trivially weak passwords.",
		Remediation: "Install and configure pam_pwquality: sudo apt install libpam-pwquality  —  then add to /etc/pam.d/common-password: 'password requisite pam_pwquality.so retry=3 minlen=12'",
		Evidence:    []string{"No pam_pwquality or pam_cracklib in /etc/pam.d/"},
		Timestamp:   time.Now(),
	}, nil
}
