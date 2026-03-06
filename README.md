# vectorscan

```
  ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝███████╗██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
    ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

> Big brother is always watching. Question everything. Especially the government.

Fast, opinionated system security audit tool. Scans your Mac for misconfigurations, weak defaults, and attack vectors — then tells you exactly what to fix. No agents, no cloud, no telemetry. Just a binary and the truth.

Currently macOS only. Linux and Windows support coming soon.

```
$ sudo vectorscan

[========================================] 100% (62/62) Third-party data sharing

  ╔══════════════════════════════════════════════════════════╗
  ║            VECTORSCAN — System Security Audit            ║
  ╚══════════════════════════════════════════════════════════╝
  Big brother is always watching. Question everything. Especially the government.

Host:            macbook.local
Platform:        darwin
OS Version:      15.3.1
Scan Date:       2026-03-06 19:42:07
Scan Duration:   6842ms

┌─ Security Score ─────────────────────────────────────────┐
│ ████████░░ [83%] Good (75%+ checks passing)              │
│ 38 of 62 checks passing | 196/248 points                 │
└──────────────────────────────────────────────────────────┘

Findings Summary:
  🔴 Critical:  1
  🟠 High:      3
  🟡 Medium:    7
  🟢 Low:       9
  ✅ Enabled:   38
  📊 Total:     62

┌─ Detailed Findings ───────────────────────────────────────┐

🔴 [PHYS-004] Automatic login enabled
   Category:    physical
   Severity:    CRITICAL
   Description: Automatic login bypasses the login screen. Anyone with
                physical access can use the computer.
   Remediation: System Settings → General → Login Options → disable Automatic login
   Evidence:
     • Automatic login: username

🟠 [SSH-003] SSH service is running
   Category:    network
   Severity:    HIGH
   Description: SSH daemon is running and accepting connections.
                If not needed, disable it to reduce attack surface.
   Remediation: System Settings → General → Sharing → Remote Login → disable
   Evidence:
     • com.openssh.sshd is loaded and running

...

└──────────────────────────────────────────────────────────┘
```

---

## Quick start

```bash
# Install directly from GitHub (requires Go 1.21+)
go install github.com/linkvectorized/vectorscan/cmd/vectorscan@latest

# Run (sudo strips PATH, so use $(which ...) or the full path)
sudo $(which vectorscan)

# Without root (partial results, warns you)
vectorscan
```

Or clone and build manually:

```bash
git clone https://github.com/linkvectorized/vectorscan
cd vectorscan
go build -o vectorscan ./cmd/vectorscan/
sudo ./vectorscan
```

---

## Output formats

```bash
./vectorscan                    # Table (default) — colored terminal output
./vectorscan -output json       # JSON — pipe to jq, feed to dashboards
./vectorscan -output csv        # CSV — spreadsheets, compliance reports
./vectorscan -output markdown   # Markdown — paste into docs or tickets
```

---

## What it checks

62 security checks across these categories:

| Category | What it covers |
|----------|---------------|
| **Permissions** | Sudoers, world-writable files, SUID binaries |
| **System** | SIP, Gatekeeper, FileVault, XProtect, firmware, secure boot |
| **Authentication** | Password policy, account lockout, empty passwords, Touch ID for sudo |
| **Network** | Open ports, SSH config, VPN, DNS-over-HTTPS, DNSSEC, Bonjour, weak ciphers |
| **Privacy** | Spotlight telemetry, Siri analytics, Apple analytics, camera/mic access, location services |
| **Persistence** | Launch agents, shell configs, kernel extensions |
| **Logging** | Audit daemon, syslog, crash reporter, log retention |
| **Credentials** | Exposed credential files, git config secrets, SSH key strength |

---

## Scoring

Weighted scoring — critical issues hurt more than low ones. Skipped checks (timeouts, insufficient privileges) are excluded from the score entirely.

| Severity | Weight | Meaning |
|----------|--------|---------|
| CRITICAL | 4 pts | Immediate risk — fix now |
| HIGH | 3 pts | Significant exposure — fix soon |
| MEDIUM | 2 pts | Weak configuration — should address |
| LOW | 1 pt | Hardening opportunity |
| INFO | 0 pts | Informational / passing check |

Every check is worth 4 points max. Passing checks earn full points. Failing checks lose points based on severity. Your score is `earned / max * 100`.

```
3 critical findings: -12 pts
2 high findings:     -6 pts
9 medium findings:   -18 pts
4 low findings:      -4 pts
                     ─────
Total deductions:    -40 pts
Max possible:        220 pts
Earned:              180 pts → 81%
```

---

## What you need

- macOS (darwin)
- Go 1.21+
- 7 seconds

---

## License

MIT — free for everyone, forever. Use it, fork it, modify it, share it.

---

*Know your attack surface. Fix it before someone else finds it.*

— [linkvectorized](https://github.com/linkvectorized)
