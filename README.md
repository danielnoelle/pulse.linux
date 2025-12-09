# PULSE - Package Utilities & Linux System Engine

**Version:** 1.0.0  
**Platform:** Debian-based Linux (Ubuntu, Linux Mint, Debian, Pop!_OS, etc.)  
**License:** Open Source  
**Language:** Python 3

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [System Requirements](#system-requirements)
4. [Installation Guide](#installation-guide)
5. [Getting Started](#getting-started)
6. [User Manual](#user-manual)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)
10. [Security Considerations](#security-considerations)
11. [Contributing](#contributing)

---

## Overview

**PULSE** is a comprehensive system administration and package management tool designed for Debian-based Linux distributions. It provides a modern graphical interface for installing packages, managing system tweaks, monitoring resources, and performing security audits.

### Key Highlights

- **Package Management**: Install, uninstall, and manage APT packages with a user-friendly GUI
- **System Tweaks**: Apply performance optimizations and system configurations
- **Security Hardening**: Automated security audits and hardening tools
- **Resource Monitoring**: Real-time system resource tracking (CPU, GPU, Memory, Disk, Network)
- **Preset Builds**: One-click configurations for Gaming, Development, and Security setups
- **Backup Automation**: BorgBackup integration with encryption and deduplication

---

## Features

### 📦 Package Management Module
- Browse packages by category (Internet, Development, Multimedia, etc.)
- View installed applications with detailed information
- Batch install/uninstall operations
- External .deb file installation support
- Package validation before installation
- Automatic dependency resolution

### ⚙️ System Tweaks Module
- **Safe Cleanup**: APT cache cleanup, orphaned package removal
- **Automated Backup**: BorgBackup configuration with AES-256 encryption
- **Security Hardening**: UFW firewall, SSH hardening, automatic updates
- **Network Optimization**: DNS configuration, BBR TCP, MAC randomization
- **System Presets**: Gaming, Development, Privacy & Security builds

### 🔍 System Monitor Module
- **Security Audit**: CIS-based security assessment with auto-fix
- **Resource Monitor**: Real-time CPU, GPU, Memory, Disk, Network tracking
- **Service Management**: View and control systemd services
- **Process Management**: Monitor and manage running processes

### 🔒 Security Features
- Input sanitization to prevent command injection
- URL validation for safe downloads
- Rotating file logs for audit trail
- Package availability validation
- User preference encryption

---

## System Requirements

### Minimum Requirements
- **OS**: Debian-based Linux (Ubuntu 20.04+, Debian 11+, Linux Mint 20+)
- **Python**: Python 3.8 or higher
- **RAM**: 2GB minimum (4GB recommended)
- **Disk**: 100MB for application + space for packages

### Required System Tools
- `apt-get` (package manager)
- `pkexec` (privilege escalation)
- `systemctl` (service management)
- `python3-tk` (Tkinter GUI library)

### Optional Dependencies
- `python3-apt` - Enhanced APT integration (recommended)
- `borgbackup` - Automated backup functionality
- `nvidia-smi` - GPU monitoring for NVIDIA cards
- `rocm-smi` - GPU monitoring for AMD cards

---

## Installation Guide

### Step 1: Install System Dependencies

```bash
# Update package lists
sudo apt update

# Install required dependencies
sudo apt install -y python3 python3-tk python3-apt policykit-1

# Optional: Install backup and monitoring tools
sudo apt install -y borgbackup
```

### Step 2: Download PULSE

```bash
# Clone or download PULSE files to a directory
mkdir -p ~/pulse
cd ~/pulse

# Copy all PULSE files here:
# - pulse.py
# - apt_manager.py
# - commands.py
# - config.py
# - tweaks.py
# - ui_helpers.py
```

### Step 3: Set Permissions

```bash
# Make the main script executable
chmod +x pulse.py

# Ensure all Python modules are readable
chmod 644 *.py
```

### Step 4: First Run

```bash
# Run PULSE
python3 pulse.py

# Or if you created desktop entry, launch from application menu
```

---

## Getting Started

### Initial Setup

1. **Launch PULSE**: Run `python3 pulse.py` from terminal
2. **Grant Permissions**: When prompted, enter your password for system operations
3. **Wait for Initialization**: PULSE will scan installed packages (may take 30-60 seconds)
4. **Select Module**: Choose between INSTALL, TWEAKS, or MONITOR modules

### Basic Workflow

#### Installing Packages
1. Click **INSTALL** module button
2. Browse categories (Internet, Development, etc.)
3. Check boxes for desired applications
4. Click **[ INSTALL ]** button
5. Authenticate when prompted
6. Wait for installation to complete

#### Applying System Tweaks
1. Click **TWEAKS** module button
2. Navigate to SYSTEM, SECURITY, or NETWORK tabs
3. Check desired tweaks
4. Click **[ RUN TWEAKS ]** button
5. Follow on-screen prompts

#### Monitoring System
1. Click **MONITOR** module button
2. Navigate to AUDIT, RESOURCES, or SERVICES tabs
3. For security audit: Click **[ RUN AUDIT ]**
4. Resources monitoring starts automatically

---

## User Manual

### Module 1: Package Installation

#### Category-Based Installation
- Navigate through tabs: Internet, Development, Multimedia, Graphics, etc.
- Each category contains curated applications
- Hover over app names to see descriptions
- Select multiple apps and install in one batch

#### Installed Apps Management
- View all installed packages in tree view
- Select packages to see detailed information
- Uninstall single or multiple packages
- Update/reinstall corrupted packages

#### External Package Installation
1. Click **[ CUSTOM DL ]** button
2. Enter .deb file path or URL
3. Supports local files and HTTP(S) downloads
4. Automatic dependency resolution

**Example:**
```
Local file: /home/user/Downloads/package.deb
Remote URL: https://example.com/software.deb
```

### Module 2: System Tweaks

#### Safe Cleanup
- Removes APT package cache
- Cleans orphaned packages
- Clears thumbnail cache
- Frees up disk space

**Commands executed:**
```bash
apt-get clean
apt-get autoremove -y
apt-get autoclean
rm -rf ~/.cache/thumbnails/*
```

#### Automated Backup (BorgBackup)
- Creates encrypted incremental backups
- AES-256-CTR encryption with HMAC-SHA256
- Chunk-level deduplication (saves space)
- LZ4 compression for speed
- Daily automated backups at 2:00 AM
- Automatic pruning (keeps 7 daily, 4 weekly, 6 monthly)

**Setup Process:**
1. Enter source directories (e.g., `/home,/etc`)
2. Enter backup destination (local or remote)
3. Save encryption passphrase (CRITICAL!)
4. System creates backup script and timer

**Manual Commands:**
```bash
# Run backup immediately
sudo /usr/local/bin/pulse-backup

# View backup archives
sudo borg list /path/to/repo

# Restore specific file
sudo borg extract ::<archive> path/to/file

# Check backup integrity
sudo borg check /path/to/repo

# View logs
tail -f /var/log/pulse-backup.log

# Check timer status
systemctl status pulse-backup.timer
```

#### Security Hardening

**Firewall Configuration:**
- Installs and enables UFW
- Default deny incoming, allow outgoing
- Allows SSH on port 2222
```bash
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp
```

**SSH Hardening:**
- Disables root login
- Changes port to 2222
- Disables password authentication (key-based only)
```bash
# Edit /etc/ssh/sshd_config
PermitRootLogin no
Port 2222
PasswordAuthentication no
```

**Automatic Security Updates:**
```bash
apt-get install -y unattended-upgrades
# Auto-applies security patches daily
```

**Privilege Escalation Hardening:**
- Disables core dumps
- Sets sudo timeout to 5 minutes
- Limits su command access
```bash
echo '* hard core 0' >> /etc/security/limits.conf
echo 'Defaults timestamp_timeout=5' >> /etc/sudoers.d/timeout
```

#### Network Optimization

**DNS Configuration:**
- Cloudflare: 1.1.1.1 (privacy-focused)
- Google: 8.8.8.8 (reliable)
```bash
echo 'nameserver 1.1.1.1' > /etc/resolv.conf
```

**BBR TCP Congestion Control:**
- Improves internet speed
- Reduces latency
- Requires reboot
```bash
echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
sysctl -p
```

**MAC Address Randomization:**
- Enhances privacy
- Randomizes hardware address
```bash
apt-get install -y macchanger
macchanger -r <interface>
```

### Module 3: System Monitor

#### Security Audit
Performs comprehensive CIS-based security assessment:

**Checks Performed:**
1. Firewall detection (UFW, firewalld, iptables)
2. Unnecessary services (telnet, rsh, cups, bluetooth)
3. SSH configuration audit
4. Critical file permissions (/etc/shadow, /etc/passwd)
5. Rootkit indicators
6. Password policy review
7. Auditd logging status
8. Automatic updates configuration

**Scoring System:**
- 85-100: Excellent ✓
- 70-84: Good ⚠
- 50-69: Needs Improvement ✗
- 0-49: Critical Risk ⛔

**Auto-Fix Feature:**
- Automatically detects fixable issues
- Applies fixes with single authentication
- Re-run audit to verify

#### Resource Monitor
Real-time system monitoring with 2x3 grid:

**Metrics Displayed:**
- **CPU Usage**: Percentage and load average
- **GPU Usage**: Utilization, temperature, VRAM (NVIDIA/AMD)
- **Memory Usage**: Used/Total in GB and percentage
- **Disk Usage**: Partition usage and available space
- **Network Activity**: Upload/download rates in MB/s
- **System Uptime**: Days, hours, minutes

**Interactive Features:**
- Click any metric to open detailed graph
- Real-time updates every second
- Historical data (last 60 seconds)

#### Services Management
- View all running systemd services
- Stop, restart, enable, disable services
- Right-click context menu for quick actions
- Double-click to refresh list

#### Process Management
- View top 100 processes sorted by CPU
- Kill processes with elevated privileges
- Change process priority (nice value)
- Sortable columns (Process, PID, CPU%, MEM%, User)

**Actions:**
- **Kill Process**: Terminate with signal 9
- **Priority High**: Nice value -10
- **Priority Normal**: Nice value 0
- **Priority Low**: Nice value 10

### Preset Builds

#### 🔄 Default/Reset Build
Restores system to default configuration
- Resets CPU governor to ondemand
- Resets network settings
- Resets swap to default (swappiness=60)

#### 🎮 Gaming Build
Optimizes for gaming performance
- **Packages**: Lutris, Wine, GameMode, OBS Studio
- **Tweaks**: Performance CPU governor, low network latency, swap optimization

#### 💻 Development Build
Complete development environment
- **Packages**: Git, Docker, build-essential, Python, Node.js, Java, PostgreSQL, Redis
- **Tweaks**: Git configuration, Docker permissions

#### 🔒 Privacy & Security Build
Enhanced privacy and security
- **Packages**: Tor Browser, GnuPG, rkhunter, ClamAV, Fail2Ban, UFW
- **Tweaks**: Firewall, MAC randomization, SSH hardening, auditd

---

## Configuration

### User Preferences
Stored in: `~/.config/pulse/settings.json`

**Saved Settings:**
- Window geometry (size and position)
- Last active module

**Manual Edit:**
```bash
nano ~/.config/pulse/settings.json
```

### Application Logs
Location: `~/.local/share/pulse/pulse.log`

**Log Rotation:**
- Maximum size: 5MB
- Backup files: 3 (pulse.log.1, pulse.log.2, pulse.log.3)
- Automatic rotation when size exceeded

**View Logs:**
```bash
# View latest logs
tail -f ~/.local/share/pulse/pulse.log

# View all logs
cat ~/.local/share/pulse/pulse.log

# Search for errors
grep ERROR ~/.local/share/pulse/pulse.log
```

### Customizing Package Categories
Edit `config.py` to add/remove applications:

```python
APPS = {
    "Internet": {
        "Your App": {"pkg": "package-name"},
        # Add more apps here
    }
}
```

---

## Troubleshooting

### Common Issues

#### 1. "python3-apt library not found"
**Symptom**: Warning on startup, limited functionality

**Solution:**
```bash
sudo apt install python3-apt
# Restart PULSE
```

#### 2. "pkexec not found"
**Symptom**: Cannot run privileged commands

**Solution:**
```bash
sudo apt install policykit-1
```

#### 3. Package installation fails
**Symptom**: Error during installation, packages not found

**Solutions:**
```bash
# Update package lists
sudo apt update

# Fix broken packages
sudo apt --fix-broken install

# Check internet connection
ping -c 4 google.com
```

#### 4. Backup script errors
**Symptom**: BorgBackup fails with passphrase error

**Solution:**
```bash
# Check passphrase file exists
sudo cat /root/.config/borg/passphrase

# Verify repository
sudo borg info /path/to/repo

# Re-run backup setup if needed
```

#### 5. GUI freezes during operations
**Symptom**: Window becomes unresponsive

**Explanation**: Normal during package downloads/installations

**Solution**: Wait for operation to complete (check terminal output)

#### 6. Permission denied errors
**Symptom**: "Permission denied" in logs

**Solution:**
```bash
# Ensure user has sudo privileges
sudo usermod -aG sudo $USER

# Re-login for group changes to take effect
```

#### 7. Monitor shows "No GPU Detected"
**Symptom**: GPU monitoring unavailable

**Solutions:**
```bash
# For NVIDIA
sudo apt install nvidia-utils

# For AMD
sudo apt install rocm-smi

# Integrated graphics: Normal, no action needed
```

#### 8. Import errors on startup
**Symptom**: "ImportError: cannot import name..."

**Solution:**
```bash
# Ensure all PULSE files are in same directory
ls -la pulse.py apt_manager.py commands.py config.py tweaks.py ui_helpers.py

# Check file permissions
chmod 644 *.py
chmod +x pulse.py
```

### Debug Mode

Run with verbose output:
```bash
# Run from terminal to see debug messages
python3 -B pulse.py

# Check for Python errors
python3 -m py_compile pulse.py
```

### Log Analysis

```bash
# Check for errors in PULSE log
grep -i error ~/.local/share/pulse/pulse.log

# Check system logs
journalctl -xe | grep pulse

# Check APT logs
cat /var/log/apt/history.log
```

---

## FAQ

### General Questions

**Q: Is PULSE safe to use?**  
A: Yes. PULSE is open-source and uses standard system tools (apt, systemctl, etc.). All operations require authentication via pkexec.

**Q: Will PULSE work on non-Debian systems?**  
A: No. PULSE is designed specifically for Debian-based distributions (Ubuntu, Linux Mint, etc.) that use APT package manager.

**Q: Can I run PULSE without GUI?**  
A: No. PULSE requires a graphical environment and X11/Wayland display server.

**Q: Does PULSE collect any data?**  
A: No. All operations are local. No telemetry or data collection.

### Package Management

**Q: Can I install multiple packages from different categories?**  
A: Yes. Select packages from any categories, then click INSTALL once.

**Q: How do I install packages not listed in PULSE?**  
A: Use the "CUSTOM DL" button for .deb files, or add them to config.py.

**Q: What happens if a package installation fails?**  
A: APT will show the error in the log. Common issues: package not found, dependency conflicts, network issues.

**Q: Can I cancel an installation in progress?**  
A: Not safely. Let it complete or use `Ctrl+C` in terminal (may leave broken packages).

### Security & Backups

**Q: Is the BorgBackup encryption secure?**  
A: Yes. Uses AES-256-CTR with HMAC-SHA256, industry-standard encryption.

**Q: What if I lose my backup passphrase?**  
A: Backups become unrecoverable. There is no password reset. Store it safely!

**Q: Do security tweaks require a reboot?**  
A: Some do (BBR TCP, kernel parameters). Most apply immediately.

**Q: Can I undo security hardening?**  
A: Manually, yes. PULSE doesn't have an automated rollback feature.

### Performance

**Q: Will PULSE slow down my system?**  
A: No. PULSE only runs when you launch it. Background tasks (backups) are scheduled.

**Q: Why is the initial package scan slow?**  
A: PULSE queries APT database for all installed packages. This is normal on first run.

**Q: Can I run PULSE on a Raspberry Pi?**  
A: Yes, if running Raspberry Pi OS (Debian-based). May be slower due to hardware.

---

## Security Considerations

### Privilege Escalation
- PULSE uses `pkexec` for authenticated privilege escalation
- All system commands require explicit user authentication
- No stored passwords or credentials

### Input Validation
- All user inputs are sanitized before execution
- Regular expression validation prevents command injection
- URL validation blocks SSRF and local file access

### Logging & Audit Trail
- All operations logged to `~/.local/share/pulse/pulse.log`
- File logs use rotating handler (5MB max, 3 backups)
- Logs include timestamps, severity, and operation details

### Network Security
- URL validation ensures HTTPS/HTTP/FTP only
- Blocks access to localhost and private IP ranges
- DNS queries use system resolver (configurable)

### File Permissions
- Configuration directory: `~/.config/pulse` (user-only)
- Log directory: `~/.local/share/pulse` (user-only)
- No world-readable sensitive files

### Best Practices
1. **Regular Updates**: Keep PULSE and system packages updated
2. **Backup Passphrases**: Store encryption keys securely (not in plain text)
3. **Review Logs**: Periodically check logs for suspicious activity
4. **Minimal Privileges**: Don't run PULSE as root user
5. **Firewall Rules**: Review UFW rules after enabling firewall

---

## Contributing

### Development Team
- Daniel Noel Guillen
- Ken Cyron Abentino
- Kean Elijah Janaban
- Kurt David Fadrigo
- Vincent Lloyd Payo

### Reporting Issues
1. Check existing issues in documentation
2. Collect log files (`~/.local/share/pulse/pulse.log`)
3. Note system details (OS version, Python version)
4. Provide steps to reproduce

### Code Structure
```
pulse/
├── pulse.py           # Main application & GUI
├── apt_manager.py     # APT package management
├── commands.py        # System command execution
├── config.py          # Configuration & constants
├── tweaks.py          # System tweaks implementation
├── ui_helpers.py      # GUI utility functions
└── README.md          # This documentation
```

### Coding Standards
- **Style**: Follow PEP 8 Python style guide
- **Comments**: Document complex logic and design decisions
- **Error Handling**: Use try-except blocks, validate inputs
- **Security**: Sanitize all user inputs, validate file paths
- **Threading**: Use daemon threads for background operations
- **Logging**: Log all significant operations

---

## License & Credits

### License
Open Source - Free to use, modify, and distribute

### Built With
- **Python 3** - Core programming language
- **Tkinter** - GUI framework
- **python3-apt** - APT package management
- **BorgBackup** - Backup solution
- **systemd** - Service management

### Acknowledgments
- Debian APT team for package management
- BorgBackup developers for encryption and deduplication
- Python community for excellent libraries

---

## Version History

### v1.0.0 (December 2025)
- Initial release
- Package management with APT integration
- System tweaks and security hardening
- Resource monitoring and process management
- Automated backup with BorgBackup
- Security audit with CIS-based scoring
- Preset builds for common use cases

---

## Support

For issues, questions, or suggestions, please:
1. Review this documentation thoroughly
2. Check the Troubleshooting section
3. Examine log files for error details
4. Contact development team with detailed information

**Happy System Administration! 🚀**

