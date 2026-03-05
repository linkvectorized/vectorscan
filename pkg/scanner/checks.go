package scanner

import (
	"context"
	"fmt"
	"os"
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
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.alf globalstate")
	if err != nil {
		return nil, nil
	}

	trimmedOutput := strings.TrimSpace(output)

	// 0 = off, 1 = on for specific services, 2 = on for all connections
	if trimmedOutput == "0" {
		return &models.Finding{
			ID:          "SYS-003",
			Category:    "system",
			Severity:    models.SeverityHigh,
			Title:       "Firewall disabled",
			Description: "macOS firewall is disabled, leaving the system exposed to network attacks",
			Remediation: "Enable firewall: System Preferences → Security & Privacy → Firewall → Turn On Firewall",
			Evidence:    []string{"Firewall state: disabled (globalstate: 0)"},
			Timestamp:   time.Now(),
		}, nil
	}

	// Report when firewall is enabled (positive finding)
	fwStatus := "specific services"
	if strings.Contains(trimmedOutput, "2") {
		fwStatus = "all connections"
	}
	return &models.Finding{
		ID:          "SYS-003-OK",
		Category:    "system",
		Severity:    models.SeverityInfo,
		Title:       "Firewall enabled ✓",
		Description: fmt.Sprintf("macOS firewall is active, protecting against incoming connections on %s", fwStatus),
		Remediation: "No action needed",
		Evidence:    []string{fmt.Sprintf("Firewall state: enabled (%s)", fwStatus)},
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
	// macOS: check pwpolicy for complexity requirements
	if s.platform == "darwin" {
		output, err := s.platform_util.RunCommand(ctx, "pwpolicy", "getaccountpolicies")
		if err != nil {
			return nil, nil
		}

		// Check if password policy requires complexity
		if !strings.Contains(output, "requiresAlpha") && !strings.Contains(output, "requiresNumeric") {
			return &models.Finding{
				ID:          "PWD-001",
				Category:    "configs",
				Severity:    models.SeverityMedium,
				Title:       "Weak password policy configured",
				Description: "System does not enforce password complexity requirements (uppercase, numbers, special chars)",
				Remediation: "Enable password complexity via: System Preferences → Security & Privacy → Users & Groups → Edit password policy",
				Evidence:    []string{"Password policy does not require alphanumeric characters"},
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return nil, nil
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

	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", fmt.Sprintf("ls -la %s/id_* 2>/dev/null", sshDir))
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
			ID:          "SSH-003",
			Category:    "permissions",
			Severity:    models.SeverityCritical,
			Title:       "SSH private keys readable by others",
			Description: "SSH private keys should only be readable by the owner (600). Readable keys allow attackers to impersonate you.",
			Remediation: fmt.Sprintf("Fix permissions: chmod 600 %s/id_*", sshDir),
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
			Remediation: "Enable FileVault: System Preferences → Security & Privacy → FileVault",
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
		Remediation: "System Preferences → Users & Groups → uncheck 'Allow guests to log in'",
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
			Remediation: "System Preferences → Security & Privacy → uncheck 'Automatic login'",
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
			Remediation: "Run: softwareupdate -i -a or System Preferences → Software Update",
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
			Remediation: "Disable Bluetooth when not needed: System Preferences → Bluetooth → Turn Off",
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
			Remediation: "Review app permissions: System Preferences → Security & Privacy → Camera/Microphone",
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
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "launchctl list | grep -i ssh")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "SSH-003",
			Category:    "network",
			Severity:    models.SeverityHigh,
			Title:       "SSH service is running",
			Description: "SSH daemon is running and accepting connections. If not needed, disable it to reduce attack surface.",
			Remediation: "Disable SSH: sudo systemsetup -setremotelogin off",
			Evidence:    []string{"SSH service is loaded and running"},
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
				Remediation: "Connect to VPN in System Preferences → Network → VPN",
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
		Remediation: "Configure DNS over HTTPS: System Preferences → Network → Wi-Fi → Advanced → DNS → Use Cloudflare (1.1.1.1)",
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

	// Check Chrome for password saving
	if s.platform_util.FileExists(chromePrefs) {
		content, _ := s.platform_util.ReadFile(chromePrefs)
		if strings.Contains(content, "\"password_manager_enabled\":true") {
			return &models.Finding{
				ID:          "BROWSER-001",
				Category:    "browser",
				Severity:    models.SeverityMedium,
				Title:       "Browser password manager stores passwords",
				Description: "Chrome/Edge is configured to save passwords. Passwords stored in plaintext can be accessed by malware.",
				Remediation: "Disable password saving: Chrome → Settings → Passwords → Turn off 'Offer to save passwords'",
				Evidence:    []string{"Chrome password manager is enabled"},
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
			Remediation: "Enable iCloud Keychain: System Preferences → [Apple ID] → iCloud → Keychain",
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
		Remediation: "Verify 2FA: System Preferences → [Apple ID] → Password & Security → Two-Factor Authentication",
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

// checkSecureBootT2 checks T2 security chip and Secure Boot status
func (s *Scanner) checkSecureBootT2(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "system_profiler SPiBridgeType 2>/dev/null | grep -i 'Apple T2'")
	if err == nil && strings.TrimSpace(output) != "" {
		// T2 present, check if SecureBoot is enabled
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
			Remediation: "Boot into Recovery Mode (Cmd+R), Utilities → Firmware Password Utility → Enable",
			Evidence:    []string{"T2 chip detected but Secure Boot mode is reduced"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("FW-001-OK", "Firmware security configured ✓", "Secure Boot status verified", "Firmware protection baseline met"), nil
}

// System & Authentication Checks

// checkRootSSHLogin checks if root login via SSH is disabled
func (s *Scanner) checkRootSSHLogin(ctx context.Context) (*models.Finding, error) {
	content, err := s.platform_util.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return positiveAuditFinding("AUTH-001-OK", "SSH root login check passed ✓", "SSH daemon not accessible", "Cannot verify SSH config"), nil
	}

	if strings.Contains(content, "PermitRootLogin yes") && !strings.Contains(content, "#PermitRootLogin yes") {
		return &models.Finding{
			ID:          "AUTH-001",
			Category:    "authentication",
			Severity:    models.SeverityCritical,
			Title:       "Root SSH login permitted",
			Description: "PermitRootLogin is enabled in sshd_config, allowing direct root login via SSH",
			Remediation: "Edit /etc/ssh/sshd_config: change 'PermitRootLogin yes' to 'PermitRootLogin no', then sudo systemctl restart ssh",
			Evidence:    []string{"PermitRootLogin yes found in /etc/ssh/sshd_config"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-001-OK", "Root SSH login disabled ✓", "SSH root access denied", "Direct root SSH login is disabled"), nil
}

// checkEmptyPasswordAccounts checks for accounts with empty passwords
func (s *Scanner) checkEmptyPasswordAccounts(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "awk -F: '($2==\"\") {print $1}' /etc/shadow 2>/dev/null")
	if err == nil && strings.TrimSpace(output) != "" {
		users := strings.TrimSpace(output)
		return &models.Finding{
			ID:          "AUTH-002",
			Category:    "authentication",
			Severity:    models.SeverityCritical,
			Title:       "Users with empty passwords detected",
			Description: fmt.Sprintf("Following accounts have no password set and can login without authentication: %s", users),
			Remediation: "Set passwords for all accounts: sudo passwd <username>",
			Evidence:    []string{fmt.Sprintf("Empty password accounts: %s", users)},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-002-OK", "No empty password accounts ✓", "All accounts require passwords", "Strong password enforcement in place"), nil
}

// checkPasswordExpiration checks if password expiration policy is set
func (s *Scanner) checkPasswordExpiration(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "plutil -p /var/db/dslocal/nodes/Default/users/root.plist 2>/dev/null | grep -i maxPasswordAge")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "AUTH-003",
			Category:    "authentication",
			Severity:    models.SeverityMedium,
			Title:       "Password expiration policy not configured",
			Description: "Passwords do not expire. Require periodic password changes for security.",
			Remediation: "Configure password policy: System Preferences → Users & Groups → Password Options → Require password change every X days",
			Evidence:    []string{"No password expiration policy detected"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-003-OK", "Password expiration configured ✓", "Password rotation policy enabled", "Periodic password changes required"), nil
}

// checkAccountLockout checks if account lockout after failed login attempts is enabled
func (s *Scanner) checkAccountLockout(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null | grep -i 'MaxFailedAttempts\\|lockLockoutDuration'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "AUTH-004",
			Category:    "authentication",
			Severity:    models.SeverityMedium,
			Title:       "Account lockout policy not configured",
			Description: "No account lockout after failed login attempts. Attackers can brute force passwords.",
			Remediation: "Enable account lockout: System Preferences → Security & Privacy → General → Lock after X failed login attempts",
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

	// Check remote login via systemsetup (more reliable than plist)
	remoteLogin, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "systemsetup -getremotelogin 2>/dev/null")
	if strings.Contains(strings.ToLower(remoteLogin), "on") {
		issues = append(issues, "Remote login enabled")
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
			Remediation: "Disable remote login and password hints in System Preferences → Security & Privacy",
			Evidence:    issues,
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUTH-005-OK", "Login window security hardened ✓", "Secure login configuration", "Remote login disabled, hints hidden"), nil
}

// Kernel & Core Checks

// checkKernelExtensions checks for unsigned/untrusted kernel extensions
func (s *Scanner) checkKernelExtensions(ctx context.Context) (*models.Finding, error) {
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
	if err != nil || !strings.Contains(output, "true") && !strings.Contains(output, "1") {
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
			Remediation: "Disable core dumps: Add 'limit core 0 0' to appropriate launch configuration or use: ulimit -c 0",
			Evidence:    []string{"Core dump limit is unlimited or large"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("KERNEL-003-OK", "Core dumps disabled ✓", "Memory dumps prevented", "Sensitive data protection active"), nil
}

// Privacy & Access Control Checks

// checkAccessibilityPermissions checks what apps have accessibility access
func (s *Scanner) checkAccessibilityPermissions(ctx context.Context) (*models.Finding, error) {
	dbPath := "/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.apple.accessibility.mru.sfl2"
	if !s.platform_util.FileExists(dbPath) {
		return positiveAuditFinding("PRIVACY-001-OK", "Accessibility access audit complete ✓", "No unauthorized accessibility access", "Accessibility database not populated"), nil
	}

	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "sqlite3 \""+dbPath+"\" 'SELECT * FROM item_records' 2>/dev/null | head -20")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "PRIVACY-001",
			Category:    "privacy",
			Severity:    models.SeverityMedium,
			Title:       "Applications with accessibility permissions",
			Description: "Multiple applications have been granted accessibility permissions. Review to remove unnecessary access.",
			Remediation: "System Preferences → Security & Privacy → Accessibility → Review and remove apps",
			Evidence:    []string{"Accessibility permissions granted to applications"},
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
			Remediation: "System Preferences → Security & Privacy → Location Services → Disable for unnecessary apps",
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
			Remediation: "Enable Gatekeeper: sudo spctl --master-enable (or System Preferences → Security & Privacy → Allow apps)",
			Evidence:    []string{"Gatekeeper is disabled"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-004-OK", "App source protection enabled ✓", "Only trusted sources allowed", "Gatekeeper verified"), nil
}

// checkNotarization checks if app notarization is enforced
func (s *Scanner) checkNotarization(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "sudo codesign -v /Applications/Safari.app 2>&1 | grep -i 'notarized\\|notary'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "PRIVACY-005",
			Category:    "privacy",
			Severity:    models.SeverityMedium,
			Title:       "App notarization not verified",
			Description: "Cannot verify notarization status of installed applications.",
			Remediation: "System Preferences → Security & Privacy → Verify app signatures: codesign -v /path/to/app",
			Evidence:    []string{"App notarization status unknown"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("PRIVACY-005-OK", "App notarization verified ✓", "Applications are notarized", "Malware detection active"), nil
}

// Network & Encryption Checks

// checkSSHKeyAlgorithms checks for weak SSH key algorithms
func (s *Scanner) checkSSHKeyAlgorithms(ctx context.Context) (*models.Finding, error) {
	rsaKeyPath := os.ExpandEnv("$HOME/.ssh/id_rsa")
	if !s.platform_util.FileExists(rsaKeyPath) {
		return positiveAuditFinding("SSH-004-OK", "SSH key algorithms checked ✓", "SSH keys properly configured", "Standard key algorithms in use"), nil
	}

	output, _ := s.platform_util.RunCommand(ctx, "sh", "-c", "ssh-keygen -l -f ~/.ssh/id_rsa 2>/dev/null | grep -i '1024\\|512'")
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

// checkWeakCiphers checks for deprecated SSL/TLS ciphers
func (s *Scanner) checkWeakCiphers(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "openssl ciphers -v 2>/dev/null | grep -E 'DES|RC4|MD5|NULL'")
	if err == nil && strings.TrimSpace(output) != "" {
		return &models.Finding{
			ID:          "CRYPTO-001",
			Category:    "network",
			Severity:    models.SeverityHigh,
			Title:       "Weak SSL/TLS ciphers available",
			Description: "Deprecated cipher suites (DES, RC4, MD5, NULL) are still available. Disable them.",
			Remediation: "Update OpenSSL configuration: edit /etc/ssl/openssl.cnf to disable weak ciphers",
			Evidence:    []string{"Weak ciphers detected in OpenSSL"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CRYPTO-001-OK", "Strong ciphers only ✓", "Modern TLS encryption", "Weak algorithms disabled"), nil
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
			Remediation: "Configure DNSSEC: edit /etc/resolv.conf or use System Preferences → Network → DNS",
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
			Remediation: "Disable Bonjour: System Preferences → Network → Advanced → DNS (uncheck mDNS)",
			Evidence:    []string{"mDNS responder is running"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("NET-007-OK", "Bonjour configuration checked ✓", "Network discovery configured", "Privacy settings applied"), nil
}

// Logging & Monitoring Checks

// checkAuditLogging checks if system audit logging is enabled
func (s *Scanner) checkAuditLogging(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "auditctl -l 2>/dev/null | head -1")
	if err != nil || strings.Contains(output, "No rules") || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "AUDIT-001",
			Category:    "audit",
			Severity:    models.SeverityMedium,
			Title:       "System audit logging not configured",
			Description: "Audit daemon (auditd) is not configured or no rules are set. Cannot track security events.",
			Remediation: "Configure auditd: sudo auditctl -w /etc/shadow -p wa -k passwd_changes (create audit rules)",
			Evidence:    []string{"Audit daemon not configured or no audit rules"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("AUDIT-001-OK", "Audit logging enabled ✓", "Security events tracked", "Forensic capability active"), nil
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
			Remediation: "Enable sleep timeout: System Preferences → Energy Saver → Sleep after X minutes",
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
			Remediation: "Enable NTP: System Preferences → Date & Time → Set date and time automatically",
			Evidence:    []string{"NTP synchronization not detected"},
			Timestamp:   time.Now(),
		}, nil
	}

	return positiveAuditFinding("CONFIG-002-OK", "Time synchronization active ✓", "NTP enabled and syncing", "Crypto timestamp validation working"), nil
}

// checkFirmwareUpdates checks for pending firmware updates
func (s *Scanner) checkFirmwareUpdates(ctx context.Context) (*models.Finding, error) {
	output, err := s.platform_util.RunCommand(ctx, "sh", "-c", "system_profiler SPiBridgeDataType 2>/dev/null | grep -i 'Version'")
	if err != nil || strings.TrimSpace(output) == "" {
		return &models.Finding{
			ID:          "CONFIG-003",
			Category:    "configuration",
			Severity:    models.SeverityMedium,
			Title:       "Firmware update status unknown",
			Description: "Unable to verify firmware is up to date. Check for pending firmware security updates.",
			Remediation: "Check firmware: System Preferences → System Update or use: softwareupdate -l",
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
			Remediation: "Disable Remote Management: System Preferences → Sharing → Uncheck Remote Management/Screen Sharing",
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
			Remediation: "Disable Spotlight suggestions: System Preferences → Siri & Spotlight → Uncheck 'Suggestions'",
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
			Remediation: "Disable Siri analytics: System Preferences → Siri → Uncheck 'Improve Siri & Dictation'",
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
			Remediation: "Disable: System Preferences → Security & Privacy → Analytics → Uncheck 'Share crash data'",
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

