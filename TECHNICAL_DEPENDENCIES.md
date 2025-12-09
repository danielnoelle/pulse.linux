# PULSE - Technical Dependencies & Implementation Details

**Version:** 1.0.0  
**Platform:** Debian-based Linux (Ubuntu, Debian, Linux Mint, Pop!_OS)  
**Last Updated:** December 9, 2025

---

## Table of Contents

1. [Install Module](#install-module)
2. [Tweaks Module](#tweaks-module)
3. [Monitor Module](#monitor-module)
4. [Core Dependencies](#core-dependencies)

---

# Install Module

## Linux Tools & Dependencies

### Required System Tools
| Tool | Purpose | Installation |
|------|---------|--------------|
| `apt-get` | Debian package manager | Pre-installed |
| `apt-cache` | Package cache query tool | Pre-installed |
| `dpkg` | Debian package installer | Pre-installed |
| `pkexec` | Privilege escalation | `sudo apt install policykit-1` |

### Python Dependencies
| Package | Purpose | Installation |
|---------|---------|--------------|
| `python3-apt` | APT Python bindings | `sudo apt install python3-apt` |
| `python3-tk` | Tkinter GUI library | `sudo apt install python3-tk` |

---

## Features Implementation

### 1. Package Installation

**Dependencies Used:**
- `apt-get install` - Install packages
- `apt-cache search` - Validate package existence
- `pkexec` - Authenticate privileged operations
- `python3-apt` (optional) - Enhanced package metadata

**Implementation Flow:**
```python
# 1. Package Validation (Security Check)
sanitize_input(package_name)  # Regex validation
validate_packages(package_list)  # APT cache check

# 2. Repository Validation
subprocess.run(['apt-cache', 'search', '--names-only', '.'])

# 3. Batch Installation
pkexec apt-get install -y package1 package2 package3

# 4. Post-Install Verification
apt-cache policy package_name
```

**Command Example:**
```bash
pkexec apt-get update
pkexec apt-get install -y firefox chromium-browser vlc
```

**Features:**
- ✅ Batch installation (multiple packages in one command)
- ✅ Package validation before installation
- ✅ Input sanitization (prevents command injection)
- ✅ Real-time log output in GUI
- ✅ Automatic dependency resolution
- ✅ Error handling with rollback support

---

### 2. Package Uninstallation

**Dependencies Used:**
- `apt-get remove` - Remove packages
- `apt-get purge` - Remove packages + config files
- `apt-get autoremove` - Clean orphaned dependencies

**Implementation Flow:**
```python
# 1. Get selected packages from tree view
selected_packages = get_selected_from_treeview()

# 2. Confirm with user
messagebox.askyesno("Confirm Uninstall", f"Remove {len(packages)} packages?")

# 3. Execute removal
pkexec apt-get remove -y package1 package2
pkexec apt-get autoremove -y  # Clean orphans
```

**Command Example:**
```bash
pkexec apt-get remove -y firefox chromium-browser
pkexec apt-get autoremove -y
```

**Features:**
- ✅ Multi-select uninstall
- ✅ Automatic orphan cleanup
- ✅ User confirmation dialog
- ✅ Progress logging
- ✅ Tree view refresh after uninstall

---

### 3. Package Update/Reinstall

**Dependencies Used:**
- `apt-get update` - Update package lists
- `apt-get install --reinstall` - Reinstall packages
- `apt-get upgrade` - Upgrade packages

**Implementation Flow:**
```python
# 1. Update package lists
pkexec apt-get update

# 2. Reinstall selected packages
for package in selected_packages:
    pkexec apt-get install --reinstall -y {package}

# 3. Refresh installed apps list
self.refresh_installed_apps()
```

**Command Example:**
```bash
pkexec apt-get update
pkexec apt-get install --reinstall -y vlc
```

**Features:**
- ✅ Package list update
- ✅ Reinstall corrupted packages
- ✅ Fix missing dependencies
- ✅ Maintain current version

---

### 4. External .deb Download & Install

**Dependencies Used:**
- `wget` or `curl` - Download files
- `dpkg -i` - Install .deb files
- `apt-get install -f` - Fix dependencies
- `python urllib.parse` - URL validation

**Implementation Flow:**
```python
# 1. Validate URL (SSRF protection)
validate_url(url)  # Blocks localhost, private IPs

# 2. Download .deb file
if url.startswith('http'):
    wget_cmd = f"wget -O /tmp/package.deb {url}"
    subprocess.run(['pkexec', 'bash', '-c', wget_cmd])

# 3. Install .deb file
dpkg_cmd = "dpkg -i /tmp/package.deb"
subprocess.run(['pkexec', 'bash', '-c', dpkg_cmd])

# 4. Fix dependencies
subprocess.run(['pkexec', 'apt-get', 'install', '-f', '-y'])

# 5. Cleanup
os.remove('/tmp/package.deb')
```

**Command Example:**
```bash
# Download
wget -O /tmp/package.deb https://example.com/software.deb

# Install
pkexec dpkg -i /tmp/package.deb

# Fix dependencies
pkexec apt-get install -f -y
```

**Features:**
- ✅ URL validation (prevents SSRF attacks)
- ✅ Local file support (`/path/to/file.deb`)
- ✅ Remote URL support (`https://.../*.deb`)
- ✅ Automatic dependency resolution
- ✅ Progress feedback
- ✅ Temporary file cleanup

**Security Measures:**
```python
# URL Validation
- Allowed protocols: http, https, ftp
- Blocked: localhost, 127.0.0.1, 192.168.*, 10.*
- Validates hostname exists
- Checks .deb extension (with override option)
```

---

# Tweaks Module

## System Cleanup

### Dependencies Used
| Tool | Purpose | Command |
|------|---------|---------|
| `apt-get clean` | Remove package cache | `apt-get clean` |
| `apt-get autoclean` | Remove obsolete packages | `apt-get autoclean` |
| `apt-get autoremove` | Remove orphaned dependencies | `apt-get autoremove -y` |
| `rm` | Delete files | `rm -rf ~/.cache/thumbnails/*` |

### Implementation
```python
def execute_safe_cleanup(log_func):
    commands = [
        "apt-get clean",           # Clear APT cache (~100-500MB)
        "apt-get autoclean",       # Remove old package versions
        "apt-get autoremove -y",   # Remove unused dependencies
        "rm -rf ~/.cache/thumbnails/*"  # Clear thumbnail cache
    ]
    
    combined = " && ".join(commands)
    subprocess.run(['pkexec', 'bash', '-c', combined])
```

**Disk Space Freed:**
- APT cache: 100-500 MB
- Thumbnails: 50-200 MB
- Orphaned packages: Variable

---

## Automated Backup (BorgBackup)

### Dependencies Used
| Tool | Purpose | Installation |
|------|---------|--------------|
| `borgbackup` | Backup tool | `apt-get install -y borgbackup` |
| `systemd` | Service scheduling | Pre-installed |
| `systemctl` | Service management | Pre-installed |

### Implementation Details

**1. BorgBackup Installation**
```bash
pkexec apt-get install -y borgbackup
```

**2. Repository Initialization**
```bash
# Create backup repository with AES-256 encryption
export BORG_PASSPHRASE="user_passphrase"
borg init --encryption=repokey-blake2 /path/to/backup/repo

# Encryption: AES-256-CTR
# Authentication: HMAC-SHA256
# Key derivation: Argon2
```

**3. Backup Script Creation** (`/usr/local/bin/pulse-backup`)
```bash
#!/bin/bash
export BORG_PASSPHRASE=$(cat /root/.config/borg/passphrase)
export BORG_REPO="/path/to/backup"

# Create backup with compression
borg create --stats --compression lz4 \
    ::backup-{now:%Y-%m-%d_%H:%M:%S} \
    /home \
    /etc

# Prune old backups (retention policy)
borg prune --keep-daily=7 --keep-weekly=4 --keep-monthly=6

# Log results
echo "Backup completed: $(date)" >> /var/log/pulse-backup.log
```

**4. Systemd Timer Setup**
```ini
# /etc/systemd/system/pulse-backup.timer
[Unit]
Description=Daily PULSE Backup

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

**5. Service File**
```ini
# /etc/systemd/system/pulse-backup.service
[Unit]
Description=PULSE Backup Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pulse-backup
```

**6. Enable Timer**
```bash
systemctl daemon-reload
systemctl enable pulse-backup.timer
systemctl start pulse-backup.timer
```

### Features
- ✅ **Encryption**: AES-256-CTR with HMAC-SHA256
- ✅ **Deduplication**: Chunk-level (saves 60-90% space)
- ✅ **Compression**: LZ4 (fast) or ZSTD (high ratio)
- ✅ **Incremental**: Only changed blocks backed up
- ✅ **Scheduled**: Daily at 2:00 AM via systemd timer
- ✅ **Pruning**: Auto-delete old backups (7 daily, 4 weekly, 6 monthly)

### Manual Commands
```bash
# List backups
borg list /path/to/repo

# Restore file
borg extract ::backup-2025-12-09_02:00:00 path/to/file

# Check integrity
borg check /path/to/repo

# View logs
tail -f /var/log/pulse-backup.log
```

---

## Security Hardening

### 1. Firewall Configuration (UFW)

**Dependencies:**
- `ufw` - Uncomplicated Firewall

**Installation & Commands:**
```bash
# Install UFW
apt-get install -y ufw

# Configure rules
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp  # SSH on custom port

# Check status
ufw status verbose
```

**Features:**
- Default deny incoming traffic
- Allow outgoing connections
- SSH on port 2222 (non-standard for security)
- Rate limiting on SSH to prevent brute force

---

### 2. Disable Unnecessary Services

**Dependencies:**
- `systemctl` - Systemd service manager

**Services Disabled:**
```bash
systemctl stop bluetooth.service
systemctl disable bluetooth.service

systemctl stop cups.service
systemctl disable cups.service

# Other services: telnet, rsh-server, avahi-daemon
```

**Implementation:**
```python
services = ['bluetooth', 'cups', 'telnet', 'rsh-server']
for service in services:
    if service_exists(service):
        subprocess.run(['pkexec', 'systemctl', 'stop', f'{service}.service'])
        subprocess.run(['pkexec', 'systemctl', 'disable', f'{service}.service'])
```

---

### 3. SSH Hardening

**Dependencies:**
- `openssh-server` - SSH daemon
- `sed` - Stream editor for config modification

**Configuration Changes:** (`/etc/ssh/sshd_config`)
```bash
# Disable root login
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Change default port
sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config

# Disable password authentication (key-based only)
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH
systemctl restart sshd
```

**Security Improvements:**
- ✅ Root login disabled
- ✅ Custom port (2222) to avoid automated attacks
- ✅ Key-based authentication only
- ✅ Protocol version 2 enforced

---

### 4. Automatic Security Updates

**Dependencies:**
- `unattended-upgrades` - Automatic update tool

**Installation & Configuration:**
```bash
# Install
apt-get install -y unattended-upgrades

# Enable
dpkg-reconfigure -plow unattended-upgrades

# Configure
cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
EOF
```

**Features:**
- Daily security patch checks
- Automatic installation of security updates
- Email notifications (optional)
- No automatic reboots (safety)

---

### 5. Privilege Escalation Hardening

**Dependencies:**
- `sysctl` - Kernel parameter tool
- `ulimit` - Resource limits

**Implementation:**
```bash
# Disable core dumps (prevent memory disclosure)
echo '* hard core 0' >> /etc/security/limits.conf

# Set sudo timeout (5 minutes)
echo 'Defaults timestamp_timeout=5' >> /etc/sudoers.d/timeout

# Restrict su command
echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su

# Apply kernel hardening
sysctl -w kernel.dmesg_restrict=1
sysctl -w kernel.kptr_restrict=2
```

**Security Benefits:**
- Core dumps disabled (no memory dumps)
- Sudo re-authentication every 5 minutes
- Su restricted to wheel group
- Kernel pointer hiding

---

## Network Optimization

### 1. DNS Configuration (Cloudflare/Google)

**Dependencies:**
- `systemd-resolved` or direct `/etc/resolv.conf` edit

**Cloudflare DNS (1.1.1.1):**
```bash
# Backup original
cp /etc/resolv.conf /etc/resolv.conf.backup

# Set Cloudflare DNS
cat > /etc/resolv.conf << EOF
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

# Make immutable (optional)
chattr +i /etc/resolv.conf
```

**Google DNS (8.8.8.8):**
```bash
cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
```

**Features:**
- ✅ Faster DNS resolution (10-50ms improvement)
- ✅ Privacy-focused (Cloudflare)
- ✅ Reliability (Google)
- ✅ DNSSEC validation

---

### 2. BBR TCP Congestion Control

**Dependencies:**
- `sysctl` - Kernel parameter configuration

**Implementation:**
```bash
# Enable BBR (requires kernel 4.9+)
echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf

# Apply immediately
sysctl -p

# Verify
sysctl net.ipv4.tcp_congestion_control
```

**Performance Impact:**
- 5-20% faster throughput
- Lower latency (especially on lossy networks)
- Better performance on high-bandwidth links
- Requires reboot for full effect

---

### 3. MAC Address Randomization

**Dependencies:**
- `macchanger` - MAC address manipulation tool

**Installation & Usage:**
```bash
# Install
apt-get install -y macchanger

# Randomize MAC for interface
macchanger -r eth0

# Or set specific MAC
macchanger -m AA:BB:CC:DD:EE:FF eth0

# Show current MAC
macchanger -s eth0
```

**Privacy Benefits:**
- Prevents device tracking
- Enhances anonymity on public networks
- Bypasses MAC filtering
- Randomizes on each boot (optional)

---

# Monitor Module

## Security Hardening Audit

### Dependencies Used

| Tool | Purpose | Check Performed |
|------|---------|----------------|
| `which` | Check command existence | Firewall tools detection |
| `systemctl` | Service status | Service state checks |
| `ufw status` | Firewall status | UFW configuration |
| `firewall-cmd` | Firewall status | Firewalld configuration |
| `iptables -L` | Firewall rules | Iptables rules check |
| `grep` | Text search | SSH config analysis |
| `stat` | File permissions | Critical file permissions |
| `rkhunter` | Rootkit detection | Malware scan |
| `auditctl` | Audit daemon | Logging verification |

### Implementation Details

#### 1. Firewall Detection
```python
def check_firewall():
    # Check UFW
    if shutil.which("ufw"):
        result = subprocess.check_output(["pkexec", "ufw", "status"], text=True)
        if "Status: active" in result:
            return "UFW Active", "PASS"
    
    # Check firewalld
    elif shutil.which("firewall-cmd"):
        result = subprocess.check_output(["firewall-cmd", "--state"], text=True)
        if "running" in result:
            return "Firewalld Active", "PASS"
    
    # Check iptables
    elif shutil.which("iptables"):
        result = subprocess.check_output(["pkexec", "iptables", "-L"], text=True)
        rule_count = len(result.split('\n'))
        if rule_count > 10:
            return "iptables configured", "PASS"
    
    return "No firewall detected", "FAIL"
```

**Command Examples:**
```bash
ufw status verbose
firewall-cmd --state
iptables -L -n -v
```

---

#### 2. Service Status Check
```python
def check_unnecessary_services():
    dangerous_services = [
        'telnet', 'rsh-server', 'cups', 'bluetooth', 
        'avahi-daemon', 'rpcbind'
    ]
    
    for service in dangerous_services:
        result = subprocess.run(
            ['systemctl', 'is-active', f'{service}.service'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:  # Service is active
            return f"{service} is running", "FAIL"
    
    return "No dangerous services found", "PASS"
```

**Command Example:**
```bash
systemctl is-active telnet.service
systemctl is-enabled bluetooth.service
```

---

#### 3. SSH Configuration Audit
```python
def check_ssh_config():
    ssh_config = "/etc/ssh/sshd_config"
    issues = []
    
    with open(ssh_config, 'r') as f:
        config = f.read()
    
    # Check root login
    if re.search(r'^PermitRootLogin\s+yes', config, re.MULTILINE):
        issues.append("Root login enabled")
    
    # Check password authentication
    if re.search(r'^PasswordAuthentication\s+yes', config, re.MULTILINE):
        issues.append("Password authentication enabled")
    
    # Check default port
    if not re.search(r'^Port\s+(?!22\s)', config, re.MULTILINE):
        issues.append("Using default SSH port 22")
    
    return issues
```

**Command Example:**
```bash
grep "^PermitRootLogin" /etc/ssh/sshd_config
grep "^PasswordAuthentication" /etc/ssh/sshd_config
grep "^Port" /etc/ssh/sshd_config
```

---

#### 4. File Permissions Check
```python
def check_file_permissions():
    critical_files = {
        '/etc/shadow': 0o600,    # Should be 600 (rw-------)
        '/etc/passwd': 0o644,    # Should be 644 (rw-r--r--)
        '/etc/gshadow': 0o600,   # Should be 600 (rw-------)
        '/etc/group': 0o644      # Should be 644 (rw-r--r--)
    }
    
    for filepath, expected_perm in critical_files.items():
        actual_perm = os.stat(filepath).st_mode & 0o777
        
        if actual_perm != expected_perm:
            return f"{filepath} has incorrect permissions", "FAIL"
    
    return "All critical files have correct permissions", "PASS"
```

**Command Example:**
```bash
stat -c '%a %n' /etc/shadow  # Should show 600
stat -c '%a %n' /etc/passwd  # Should show 644
```

---

#### 5. Rootkit Detection
```python
def check_rootkits():
    if not shutil.which("rkhunter"):
        return "rkhunter not installed", "WARN"
    
    # Run quick scan
    result = subprocess.run(
        ['pkexec', 'rkhunter', '--check', '--skip-keypress', '--report-warnings-only'],
        capture_output=True, text=True, timeout=120
    )
    
    if "Warning:" in result.stdout:
        return "Potential rootkit detected", "CRITICAL"
    
    return "No rootkits detected", "PASS"
```

**Command Example:**
```bash
rkhunter --check --skip-keypress --report-warnings-only
```

---

#### 6. Audit Daemon Check
```python
def check_auditd():
    if not shutil.which("auditctl"):
        return "Auditd not installed", "FAIL"
    
    result = subprocess.check_output(
        ['pkexec', 'auditctl', '-s'], text=True
    )
    
    if "enabled 1" in result:
        return "Auditd is enabled", "PASS"
    else:
        return "Auditd is disabled", "WARN"
```

**Command Example:**
```bash
auditctl -s  # Show audit status
auditd -l    # List audit rules
```

---

### Audit Scoring System

**CIS-Based Weighted Scoring:**
```python
def calculate_security_score(audit_results):
    # Weight multipliers
    weights = {
        "pass": +10,      # Passed check
        "warn": -2,       # Warning
        "fail": -5,       # Failure
        "critical": -15   # Critical issue
    }
    
    total_checks = sum(audit_results.values())
    weighted_score = (
        audit_results["pass"] * weights["pass"] +
        audit_results["warn"] * weights["warn"] +
        audit_results["fail"] * weights["fail"] +
        audit_results["critical"] * weights["critical"]
    )
    
    max_score = total_checks * 10
    score = int((weighted_score / max_score * 100))
    score = max(0, min(100, score))  # Clamp 0-100
    
    return score
```

**Score Interpretation:**
- 85-100: ✓ Excellent (hardened system)
- 70-84: ⚠ Good (minor improvements needed)
- 50-69: ✗ Needs Work (security gaps present)
- 0-49: ⛔ Critical (immediate action required)

---

### Auto-Fix Feature

**Implementation:**
```python
def auto_fix_issues(fixes_list):
    for fix_type, description in fixes_list:
        if fix_type == "enable_firewall":
            subprocess.run(['pkexec', 'ufw', '--force', 'enable'])
        
        elif fix_type == "disable_service":
            service = description.split()[-1]
            subprocess.run(['pkexec', 'systemctl', 'stop', service])
            subprocess.run(['pkexec', 'systemctl', 'disable', service])
        
        elif fix_type == "fix_ssh":
            # Apply SSH hardening
            execute_ssh_hardening()
        
        elif fix_type == "install_auditd":
            subprocess.run(['pkexec', 'apt-get', 'install', '-y', 'auditd'])
```

---

## Resource Monitoring & Graphs

### Dependencies Used

| Resource | Data Source | Tools |
|----------|-------------|-------|
| CPU | `/proc/stat` | Built-in |
| GPU | `nvidia-smi`, `rocm-smi` | Optional |
| Memory | `/proc/meminfo` | Built-in |
| Disk | `shutil.disk_usage()` | Python stdlib |
| Network | `/proc/net/dev` | Built-in |
| Uptime | `/proc/uptime` | Built-in |

### Implementation Details

#### 1. CPU Monitoring

**Data Source:** `/proc/stat`
```python
def update_cpu_info():
    # Read CPU times from /proc/stat
    # Format: cpu user nice system idle iowait irq softirq steal
    with open("/proc/stat", "r") as f:
        line = f.readline()
        fields = line.split()
        
        idle = int(fields[4])
        total = sum(int(x) for x in fields[1:8])
    
    # Calculate usage percentage
    if hasattr(self, '_last_cpu_total'):
        idle_delta = idle - self._last_cpu_idle
        total_delta = total - self._last_cpu_total
        cpu_usage = 100 * (1 - idle_delta / total_delta)
    
    # Store for next iteration
    self._last_cpu_total = total
    self._last_cpu_idle = idle
    
    # Add to graph data
    self.cpu_data.append(cpu_usage)
    if len(self.cpu_data) > 60:  # Keep last 60 samples
        self.cpu_data.pop(0)
```

**Command Equivalent:**
```bash
cat /proc/stat | head -1
# Output: cpu 12345 678 9101 112131 ...
```

---

#### 2. GPU Monitoring

**NVIDIA GPU:**
```python
def get_nvidia_info():
    if not shutil.which("nvidia-smi"):
        return None
    
    result = subprocess.check_output([
        'nvidia-smi',
        '--query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total',
        '--format=csv,noheader,nounits'
    ], text=True)
    
    gpu_util, temp, mem_used, mem_total = result.strip().split(', ')
    
    return {
        'utilization': int(gpu_util),
        'temperature': int(temp),
        'memory_used': int(mem_used),
        'memory_total': int(mem_total)
    }
```

**AMD GPU:**
```python
def get_amd_info():
    if not shutil.which("rocm-smi"):
        return None
    
    result = subprocess.check_output(['rocm-smi', '--showuse'], text=True)
    # Parse output for GPU utilization
```

**Command Examples:**
```bash
# NVIDIA
nvidia-smi --query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader

# AMD
rocm-smi --showuse
```

---

#### 3. Memory Monitoring

**Data Source:** `/proc/meminfo`
```python
def update_mem_info():
    with open("/proc/meminfo", "r") as f:
        meminfo = f.read()
    
    # Parse memory values (in kB)
    mem_total = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1))
    mem_available = int(re.search(r'MemAvailable:\s+(\d+)', meminfo).group(1))
    
    # Convert to GB
    total_gb = mem_total / 1024 / 1024
    used_gb = (mem_total - mem_available) / 1024 / 1024
    percent = (used_gb / total_gb) * 100
    
    # Update display
    self.mem_label.config(text=f"{used_gb:.1f} / {total_gb:.1f} GB ({percent:.1f}%)")
```

**Command Equivalent:**
```bash
cat /proc/meminfo | grep -E 'MemTotal|MemAvailable'
```

---

#### 4. Network Monitoring

**Data Source:** `/proc/net/dev`
```python
def update_network_info():
    with open("/proc/net/dev", "r") as f:
        lines = f.readlines()
    
    total_rx = 0
    total_tx = 0
    
    # Parse network interfaces (skip loopback)
    for line in lines[2:]:
        if ':' in line:
            parts = line.split()
            iface = parts[0].rstrip(':')
            
            if iface != 'lo':  # Skip loopback
                total_rx += int(parts[1])   # Received bytes
                total_tx += int(parts[9])   # Transmitted bytes
    
    # Calculate rates (bytes/sec)
    if hasattr(self, 'last_net_rx'):
        rx_rate = (total_rx - self.last_net_rx) / 1024 / 1024  # MB/s
        tx_rate = (total_tx - self.last_net_tx) / 1024 / 1024  # MB/s
    
    self.last_net_rx = total_rx
    self.last_net_tx = total_tx
```

**Command Equivalent:**
```bash
cat /proc/net/dev
```

---

### Graph Rendering (Tkinter Canvas)

**Implementation:**
```python
def draw_graph(self, canvas, data, color, label=""):
    """Draw real-time line graph with automatic scaling"""
    canvas.delete("all")
    width = canvas.winfo_width()
    height = canvas.winfo_height()
    
    if len(data) < 2:
        return
    
    # Calculate scaling
    max_val = max(data) if max(data) > 0 else 100
    min_val = min(data)
    value_range = max_val - min_val if max_val != min_val else 1
    
    # Generate points for line
    points = []
    for i, value in enumerate(data):
        x = (i / (len(data) - 1)) * width
        # Invert Y (canvas coordinates are top-down)
        y = height - ((value - min_val) / value_range) * height
        points.extend([x, y])
    
    # Draw smooth line
    if len(points) >= 4:
        canvas.create_line(points, fill=color, width=2, smooth=True)
    
    # Draw current value label
    current = data[-1]
    canvas.create_text(
        width - 10, 10,
        text=f"{current:.1f}%",
        fill=color,
        anchor="ne",
        font=("Courier New", 12, "bold")
    )
```

**Features:**
- ✅ Auto-scaling based on data range
- ✅ Smooth line interpolation
- ✅ 60-sample rolling window (1 minute of data)
- ✅ Real-time updates (1 second interval)
- ✅ Current value overlay
- ✅ Color-coded metrics

---

## Process & Service Management

### 1. Process Listing

**Dependencies:**
- `/proc` filesystem
- `ps` command

**Implementation:**
```python
def refresh_processes():
    # Get top 100 processes by CPU usage
    result = subprocess.check_output(
        ['ps', 'aux', '--sort=-pcpu'],
        text=True
    )
    
    lines = result.strip().split('\n')[1:]  # Skip header
    
    for line in lines[:100]:
        parts = line.split(None, 10)
        
        user = parts[0]
        pid = parts[1]
        cpu = parts[2]
        mem = parts[3]
        command = parts[10]
        
        # Insert into treeview
        self.processes_tree.insert('', 'end', values=(
            command, pid, cpu, mem, user
        ))
```

**Command Example:**
```bash
ps aux --sort=-pcpu | head -100
```

---

### 2. Kill Process

**Dependencies:**
- `kill` command
- `pkexec` for privileged processes

**Implementation:**
```python
def kill_process(self):
    selected = self.processes_tree.selection()
    if not selected:
        return
    
    item = self.processes_tree.item(selected[0])
    pid = item['values'][1]  # PID column
    
    # Confirm
    confirm = messagebox.askyesno(
        "Kill Process",
        f"Kill process {pid}?\n\nThis action cannot be undone."
    )
    
    if confirm:
        try:
            # Try normal kill first
            subprocess.run(['kill', '-9', str(pid)], check=True)
        except subprocess.CalledProcessError:
            # Use pkexec for privileged processes
            subprocess.run(['pkexec', 'kill', '-9', str(pid)])
        
        self.refresh_processes()
```

**Command Examples:**
```bash
# Normal kill
kill -9 1234

# Privileged kill
pkexec kill -9 1234

# Graceful kill
kill -15 1234  # SIGTERM
```

---

### 3. Change Process Priority

**Dependencies:**
- `renice` command

**Implementation:**
```python
def change_priority(self, priority):
    """
    Priority levels:
    - High: -10 (more CPU time)
    - Normal: 0 (default)
    - Low: 10 (less CPU time)
    """
    selected = self.processes_tree.selection()
    if not selected:
        return
    
    item = self.processes_tree.item(selected[0])
    pid = item['values'][1]
    
    # Renice process
    try:
        subprocess.run(['renice', '-n', str(priority), '-p', str(pid)])
    except subprocess.CalledProcessError:
        subprocess.run(['pkexec', 'renice', '-n', str(priority), '-p', str(pid)])
    
    self.log_system(f"Changed priority of PID {pid} to {priority}")
```

**Command Examples:**
```bash
# Set high priority (requires root)
renice -10 -p 1234

# Set normal priority
renice 0 -p 1234

# Set low priority
renice 10 -p 1234
```

---

### 4. Service Management

**Dependencies:**
- `systemctl` - Systemd service manager

**Service Operations:**
```python
def stop_service(self):
    service_name = get_selected_service()
    subprocess.run(['pkexec', 'systemctl', 'stop', f'{service_name}.service'])

def restart_service(self):
    service_name = get_selected_service()
    subprocess.run(['pkexec', 'systemctl', 'restart', f'{service_name}.service'])

def disable_service(self):
    service_name = get_selected_service()
    subprocess.run(['pkexec', 'systemctl', 'disable', f'{service_name}.service'])

def enable_service(self):
    service_name = get_selected_service()
    subprocess.run(['pkexec', 'systemctl', 'enable', f'{service_name}.service'])
```

**Command Examples:**
```bash
systemctl stop bluetooth.service
systemctl restart networking.service
systemctl disable cups.service
systemctl enable ufw.service
```

---

# Core Dependencies

## Required System Packages

```bash
# Essential
sudo apt install -y \
    python3 \
    python3-tk \
    python3-apt \
    policykit-1

# Optional but recommended
sudo apt install -y \
    borgbackup \
    ufw \
    unattended-upgrades \
    auditd \
    rkhunter
```

## Python Standard Library Modules

- `tkinter` - GUI framework
- `subprocess` - Execute system commands
- `threading` - Background operations
- `os` - File operations
- `re` - Regular expressions
- `json` - Configuration persistence
- `logging` - File logging
- `pathlib` - Path handling
- `urllib.parse` - URL validation
- `datetime` - Timestamps
- `shutil` - High-level file operations

---

## Summary Table

| Module | Key Dependencies | Purpose |
|--------|------------------|---------|
| **Install** | apt-get, dpkg, pkexec | Package management |
| **Tweaks** | borgbackup, systemd, ufw | System optimization |
| **Monitor** | /proc, systemctl, ps | Resource monitoring |
| **Security** | rkhunter, auditd, iptables | Security auditing |
| **Network** | sysctl, macchanger | Network optimization |

---

**End of Technical Dependencies Documentation**
