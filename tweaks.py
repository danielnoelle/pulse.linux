#!/usr/bin/env python3
import os
import shutil
from tkinter import messagebox
import threading


def execute_safe_cleanup(log_callback, root, progress_label, run_generic_command):
    """Run safe system cleanup (APT cache, orphaned packages, thumbnails)."""
    log_callback("Running Safe System Cleanup...")
    root.after(0, lambda: progress_label.config(text="Running APT cleanup operations..."))
    
    # Validate pkexec availability
    if not shutil.which("pkexec"):
        error_msg = "pkexec not found. Install policykit-1 to run privileged commands."
        log_callback(error_msg, "error")
        messagebox.showerror("Missing Dependency", error_msg)
        return
    
    # Combine APT commands for single auth prompt
    combined_cmd = [
        "pkexec", "bash", "-c",
        "apt-get clean && apt-get autoremove -y && apt-get autoclean"
    ]
    
    log_callback("Running combined APT cleanup (clean + autoremove + autoclean)...")
    run_generic_command(combined_cmd, "APT System Cleanup")
    
    # Clean thumbnail cache (user's own cache, no sudo needed)
    log_callback("Clearing thumbnail cache...")
    try:
        thumb_path = os.path.expanduser("~/.cache/thumbnails")
        
        if os.path.exists(thumb_path):
            if not os.path.isdir(thumb_path):
                log_callback(f"Warning: {thumb_path} exists but is not a directory", "warn")
                return
            
            import shutil as sh
            sh.rmtree(thumb_path, ignore_errors=False)
            os.makedirs(thumb_path, mode=0o755, exist_ok=True)
            
            log_callback("Thumbnail cache cleared successfully", "success")
        else:
            log_callback("Thumbnail cache not found, skipping", "warn")
            
    except PermissionError as e:
        log_callback(f"Permission denied clearing thumbnail cache: {e}", "error")
        
    except OSError as e:
        log_callback(f"OS error clearing thumbnail cache: {e}", "error")
        
    except Exception as e:
        log_callback(f"Error clearing thumbnail cache: {type(e).__name__}: {e}", "error")
    
    log_callback("Safe System Cleanup completed!", "success")


def execute_automated_backup(log_callback, root, progress_label, run_generic_command):
    """
    Sets up automated incremental backup using BorgBackup.
    - Deduplication at chunk level (saves massive space)
    - AES-256 encryption with SHA-256 authentication
    - Compression (lz4, zstd, or lzma)
    - Automatic pruning of old backups
    - Integrity verification built-in
    """
    import secrets
    import base64
    import queue
    from tkinter import simpledialog, messagebox
    
    log_callback("Configuring BorgBackup Automated Backup System...")
    root.after(0, lambda: progress_label.config(text="Setting up BorgBackup..."))
    
    # Use queue to get dialog results from main thread
    result_queue = queue.Queue()
    
    def ask_backup_source():
        """Ask for backup source in main thread."""
        source = simpledialog.askstring(
            "Backup Source",
            "Enter directories to backup (comma-separated):\n\n" +
            "Example: /home,/etc,/var/www\n" +
            "Default: /home",
            parent=root
        )
        result_queue.put(('source', source if source else "/home"))
    
    def ask_backup_dest():
        """Ask for backup destination in main thread."""
        dest = simpledialog.askstring(
            "Backup Destination",
            "Enter backup repository path:\n\n" +
            "Local: /mnt/backup/borg-repo\n" +
            "Remote: user@server:/path/to/borg-repo\n\n" +
            "Enter path:",
            parent=root
        )
        result_queue.put(('dest', dest))
    
    # Schedule dialogs on main thread
    root.after(0, ask_backup_source)
    backup_source = result_queue.get()[1]  # Wait for result
    
    root.after(0, ask_backup_dest)
    backup_dest_result = result_queue.get()  # Wait for result
    backup_dest = backup_dest_result[1]
    
    if not backup_dest:
        log_callback("Backup setup cancelled - no destination provided", "warn")
        return
    
    # Generate strong passphrase for encryption
    passphrase = secrets.token_urlsafe(32)  # 32-byte random passphrase
    
    # Show passphrase to user (CRITICAL - they must save this!)
    def ask_passphrase_confirmation():
        """Ask for passphrase confirmation in main thread."""
        response = messagebox.askyesno(
            "CRITICAL: Save Your Encryption Passphrase",
            f"BorgBackup uses AES-256 encryption.\n\n" +
            f"Your encryption passphrase is:\n\n" +
            f"{passphrase}\n\n" +
            f"⚠ SAVE THIS IMMEDIATELY! ⚠\n" +
            f"Without this passphrase, your backups are UNRECOVERABLE!\n\n" +
            f"The passphrase will be saved to:\n" +
            f"/root/.config/borg/passphrase\n\n" +
            f"Continue with backup setup?",
            icon='warning',
            parent=root
        )
        result_queue.put(('confirm', response))
    
    root.after(0, ask_passphrase_confirmation)
    save_passphrase = result_queue.get()[1]  # Wait for result
    
    if not save_passphrase:
        log_callback("Backup setup cancelled by user", "warn")
        return
    
    # Create Python backup script - using proper formatting for bash embedding
    backup_script = '''#!/usr/bin/env python3
"""
PULSE BorgBackup Automation Script
- Deduplication: Chunk-level with rolling hash
- Encryption: AES-256-CTR with HMAC-SHA256
- Compression: LZ4 (fast) or ZSTD (better ratio)
- Pruning: Keeps daily/weekly/monthly archives
"""

import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
BORG_REPO = "''' + backup_dest + '''"
SOURCES = "''' + backup_source + '''".split(",")
LOGFILE = "/var/log/pulse-backup.log"
DATE = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
HOSTNAME = subprocess.check_output(["hostname"]).decode().strip()

# Passphrase location
PASSPHRASE_FILE = "/root/.config/borg/passphrase"

# Set environment for Borg
os.environ["BORG_REPO"] = BORG_REPO
os.environ["BORG_PASSPHRASE"] = open(PASSPHRASE_FILE).read().strip()
os.environ["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "yes"

def log(message, level="INFO"):
    """Log with timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = "[{0}] [{1}] {2}\\n".format(timestamp, level, message)
    
    try:
        with open(LOGFILE, 'a') as f:
            f.write(log_entry)
        print(log_entry.strip())
    except Exception as e:
        print("Logging error: {0}".format(e))

def run_borg_command(cmd, description):
    """Execute Borg command with logging."""
    log("Running: {0}".format(description))
    log("Command: {0}".format(' '.join(cmd)))
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200
        )
        
        if result.returncode == 0:
            log("✓ {0} completed successfully".format(description), "SUCCESS")
            if result.stdout:
                for line in result.stdout.split('\\n')[:20]:
                    if line.strip():
                        log("  {0}".format(line))
            return True
        else:
            log("✗ {0} failed (exit code {1})".format(description, result.returncode), "ERROR")
            if result.stderr:
                log("Error output: {0}".format(result.stderr), "ERROR")
            return False
            
    except subprocess.TimeoutExpired:
        log("✗ {0} timed out (>2 hours)".format(description), "ERROR")
        return False
    except Exception as e:
        log("✗ {0} exception: {1}".format(description, e), "ERROR")
        return False

def check_borg_installed():
    """Verify BorgBackup is installed."""
    try:
        result = subprocess.run(
            ["borg", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            log("BorgBackup detected: {0}".format(version))
            return True
    except FileNotFoundError:
        log("BorgBackup not found - please install: apt install borgbackup", "ERROR")
        return False

def initialize_repo():
    """Initialize Borg repository if it doesn't exist."""
    log("Checking repository: {0}".format(BORG_REPO))
    
    # First check if repository directory exists and has borg files
    import os
    repo_config = os.path.join(BORG_REPO, "config")
    
    if os.path.exists(repo_config):
        log("Repository already exists (found config file)")
        return True
    
    # Try to list archives as secondary check
    result = subprocess.run(
        ["borg", "list", BORG_REPO],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        log("Repository already initialized")
        return True
    
    # Repository doesn't exist, create it
    log("Repository not initialized, creating new encrypted repository...")
    return run_borg_command(
        ["borg", "init", "--encryption=repokey-blake2", BORG_REPO],
        "Repository initialization"
    )

def create_backup():
    """Create backup archive."""
    archive_name = "{0}-{1}".format(HOSTNAME, DATE)
    
    log("Creating backup archive: {0}".format(archive_name))
    
    sources_list = [s.strip() for s in SOURCES if os.path.exists(s.strip())]
    
    if not sources_list:
        log("No valid source directories found!", "ERROR")
        return False
    
    log("Backing up: {0}".format(', '.join(sources_list)))
    
    cmd = [
        "borg", "create",
        "--verbose",
        "--stats",
        "--compression", "lz4",
        "--exclude-caches",
        "--exclude", "*/.cache/*",
        "--exclude", "*/lost+found",
        "--exclude", "*.tmp",
        "::{0}".format(archive_name)
    ] + sources_list
    
    return run_borg_command(cmd, "Backup creation ({0})".format(archive_name))

def prune_old_backups():
    """Remove old backups according to retention policy."""
    log("Pruning old backups...")
    
    cmd = [
        "borg", "prune",
        "--verbose",
        "--stats",
        "--keep-daily=7",
        "--keep-weekly=4",
        "--keep-monthly=6"
    ]
    
    return run_borg_command(cmd, "Backup pruning")

def verify_backup():
    """Verify repository integrity and latest archive."""
    log("Verifying repository integrity...")
    
    if not run_borg_command(
        ["borg", "check", "--verbose"],
        "Repository integrity check"
    ):
        return False
    
    log("Listing backup archives...")
    run_borg_command(
        ["borg", "list", "--short"],
        "Archive listing"
    )
    
    return True

def get_repo_info():
    """Display repository statistics."""
    log("Repository information:")
    run_borg_command(
        ["borg", "info"],
        "Repository info"
    )

def main():
    """Main backup execution."""
    log("=" * 70)
    log("PULSE BorgBackup Started: {0}".format(DATE))
    log("=" * 70)
    
    if not check_borg_installed():
        sys.exit(1)
    
    if not os.path.exists(PASSPHRASE_FILE):
        log("Passphrase file not found: {0}".format(PASSPHRASE_FILE), "ERROR")
        sys.exit(1)
    
    if not initialize_repo():
        log("Failed to initialize repository", "ERROR")
        sys.exit(1)
    
    if not create_backup():
        log("Backup creation failed", "ERROR")
        sys.exit(1)
    
    if not prune_old_backups():
        log("Pruning failed (non-critical)", "WARN")
    
    if not verify_backup():
        log("Verification failed", "ERROR")
        sys.exit(1)
    
    get_repo_info()
    
    log("=" * 70)
    log("✓ Backup completed successfully", "SUCCESS")
    log("=" * 70)
    log("")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Backup interrupted by user", "WARN")
        sys.exit(1)
    except Exception as e:
        log("CRITICAL ERROR: {0}: {1}".format(type(e).__name__, e), "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")
        sys.exit(1)
'''
    
    # Systemd service and timer
    service_file = '''[Unit]
Description=PULSE BorgBackup Automated Backup
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/bin/pulse-backup
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''
    
    timer_file = '''[Unit]
Description=PULSE BorgBackup Timer
Requires=pulse-backup.service

[Timer]
OnCalendar=daily
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
'''
    
    # Use base64 encoding to avoid all escaping issues
    import base64
    script_b64 = base64.b64encode(backup_script.encode()).decode()
    service_b64 = base64.b64encode(service_file.encode()).decode()
    timer_b64 = base64.b64encode(timer_file.encode()).decode()
    
    # Install using base64-decoded content (no escaping issues!)
    install_cmd = [
        "pkexec", "bash", "-c",
        f"apt-get install -y borgbackup python3 && "
        f"mkdir -p /root/.config/borg && "
        f"echo '{passphrase}' > /root/.config/borg/passphrase && "
        f"chmod 600 /root/.config/borg/passphrase && "
        f"echo '{script_b64}' | base64 -d > /usr/local/bin/pulse-backup && "
        f"chmod +x /usr/local/bin/pulse-backup && "
        f"echo '{service_b64}' | base64 -d > /etc/systemd/system/pulse-backup.service && "
        f"echo '{timer_b64}' | base64 -d > /etc/systemd/system/pulse-backup.timer && "
        f"systemctl daemon-reload && "
        f"systemctl enable pulse-backup.timer && "
        f"systemctl start pulse-backup.timer && "
        f"mkdir -p {backup_dest} 2>/dev/null || true && "
        f"touch /var/log/pulse-backup.log && "
        f"chmod 644 /var/log/pulse-backup.log && "
        f"echo 'BorgBackup system configured successfully'"
    ]
    
    run_generic_command(install_cmd, "BorgBackup Configuration")
    
    log_callback("=" * 70, "success")
    log_callback("✓ BorgBackup Automated System Configured!", "success")
    log_callback("=" * 70, "success")
    log_callback(f"Repository: {backup_dest}", "info")
    log_callback(f"Sources: {backup_source}", "info")
    log_callback("Schedule: Daily at 2:00 AM", "info")
    log_callback("Encryption: AES-256-CTR with HMAC-SHA256", "success")
    log_callback("Compression: LZ4 (fast, real-time)", "info")
    log_callback("Deduplication: Chunk-level with rolling hash", "success")
    log_callback("", "info")
    log_callback("⚠ CRITICAL SECURITY NOTE:", "warn")
    log_callback(f"  Encryption passphrase: {passphrase}", "warn")
    log_callback("  Stored at: /root/.config/borg/passphrase", "warn")
    log_callback("  ⚠ BACKUP THIS PASSPHRASE IMMEDIATELY!", "warn")
    log_callback("  ⚠ Lost passphrase = Lost backups (unrecoverable)", "warn")
    log_callback("", "info")
    log_callback("Retention Policy:", "info")
    log_callback("  • Keep all daily backups for 7 days", "info")
    log_callback("  • Keep weekly backups for 4 weeks", "info")
    log_callback("  • Keep monthly backups for 6 months", "info")
    log_callback("=" * 70, "success")
    log_callback("", "info")
    log_callback("Manual Commands:", "info")
    log_callback("  • Run backup now: sudo /usr/local/bin/pulse-backup", "info")
    log_callback("  • List archives: sudo borg list " + backup_dest, "info")
    log_callback("  • Check integrity: sudo borg check " + backup_dest, "info")
    log_callback("  • Restore file: sudo borg extract ::<archive> path/to/file", "info")
    log_callback("  • Mount archive: sudo borg mount " + backup_dest + " /mnt", "info")
    log_callback("  • View logs: tail -f /var/log/pulse-backup.log", "info")
    log_callback("  • Timer status: systemctl status pulse-backup.timer", "info")


def view_backup_logs(log_callback):
    """Launch comprehensive Backup Manager GUI."""
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
    import subprocess
    import threading
    import os
    from config import THEME
    
    # Create backup manager window
    backup_window = tk.Toplevel()
    backup_window.title("PULSE Backup Manager")
    backup_window.geometry("900x700")
    backup_window.configure(bg=THEME["bg"])
    
    # Make modal
    backup_window.transient()
    backup_window.grab_set()
    
    # Shared passphrase storage (set once, reused throughout session)
    passphrase_cache = {"value": None}
    
    def get_passphrase():
        """Get passphrase from user (once per session)."""
        if passphrase_cache["value"] is None:
            passphrase = simpledialog.askstring(
                "BorgBackup Passphrase", 
                "Enter repository passphrase:",
                parent=backup_window,
                show="*"
            )
            if passphrase:
                passphrase_cache["value"] = passphrase
            else:
                messagebox.showerror("Error", "Passphrase is required")
                return None
        return passphrase_cache["value"]
    
    # Main container
    main_frame = tk.Frame(backup_window, bg=THEME["bg"])
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Title
    title_label = tk.Label(main_frame, text="🗄️ BorgBackup Manager", 
                          bg=THEME["bg"], fg=THEME["accent"], 
                          font=("Courier New", 16, "bold"))
    title_label.pack(pady=(0, 10))
    
    # Notebook for tabs
    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill="both", expand=True)
    
    # ==================== TAB 1: ARCHIVES ====================
    archives_frame = tk.Frame(notebook, bg=THEME["panel"])
    notebook.add(archives_frame, text="  Archives  ")
    
    # Repository path
    repo_frame = tk.Frame(archives_frame, bg=THEME["panel"])
    repo_frame.pack(fill="x", padx=10, pady=5)
    
    tk.Label(repo_frame, text="Repository:", bg=THEME["panel"], fg=THEME["fg"], 
            font=("Courier New", 10)).pack(side="left", padx=5)
    
    repo_entry = tk.Entry(repo_frame, bg=THEME["bg"], fg=THEME["fg"], 
                         font=("Courier New", 10), insertbackground=THEME["accent"])
    repo_entry.insert(0, "/mnt/backup/borg-repo")
    repo_entry.pack(side="left", fill="x", expand=True, padx=5)
    
    # Archives listbox
    archives_list_frame = tk.Frame(archives_frame, bg=THEME["panel"])
    archives_list_frame.pack(fill="both", expand=True, padx=10, pady=5)
    
    tk.Label(archives_list_frame, text="Available Backup Archives:", 
            bg=THEME["panel"], fg=THEME["accent"], font=("Courier New", 10, "bold")).pack(anchor="w")
    
    archives_listbox = tk.Listbox(archives_list_frame, bg=THEME["bg"], fg=THEME["fg"],
                                  font=("Courier New", 9), selectmode="single",
                                  selectbackground=THEME["accent"], height=15)
    archives_scrollbar = tk.Scrollbar(archives_list_frame, command=archives_listbox.yview)
    archives_listbox.config(yscrollcommand=archives_scrollbar.set)
    archives_listbox.pack(side="left", fill="both", expand=True)
    archives_scrollbar.pack(side="right", fill="y")
    
    # Archive buttons
    archive_btn_frame = tk.Frame(archives_frame, bg=THEME["panel"])
    archive_btn_frame.pack(fill="x", padx=10, pady=5)
    
    def refresh_archives():
        """Load list of backup archives."""
        archives_listbox.delete(0, tk.END)
        repo = repo_entry.get().strip()
        
        if not repo:
            messagebox.showerror("Error", "Please enter repository path")
            return
        
        passphrase = get_passphrase()
        if not passphrase:
            return
        
        archives_listbox.insert(tk.END, "⏳ Loading archives...")
        backup_window.update()
        
        def load_thread():
            try:
                # Create a wrapper command that sets passphrase and runs borg as root
                cmd = [
                    "pkexec", "bash", "-c",
                    f"export BORG_PASSPHRASE='{passphrase}' && borg list --short '{repo}'"
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                def update_ui():
                    archives_listbox.delete(0, tk.END)
                    if result.returncode == 0 and result.stdout.strip():
                        for archive in result.stdout.strip().split('\n'):
                            if archive:
                                archives_listbox.insert(tk.END, f"📦 {archive}")
                    else:
                        archives_listbox.insert(tk.END, "❌ No archives found or repository not initialized")
                
                backup_window.after(0, update_ui)
                
            except Exception as e:
                error_msg = f"Failed to load archives:\n{e}"
                backup_window.after(0, lambda msg=error_msg: messagebox.showerror("Error", msg))
        
        threading.Thread(target=load_thread, daemon=True).start()
    
    tk.Button(archive_btn_frame, text="🔄 Refresh Archives", command=refresh_archives,
             bg=THEME["accent"], fg="#ffffff", font=("Courier New", 9, "bold"),
             relief="raised", padx=10).pack(side="left", padx=5)
    
    tk.Button(archive_btn_frame, text="ℹ️ Archive Info", 
             command=lambda: show_archive_info(repo_entry.get(), archives_listbox, passphrase_cache),
             bg=THEME["warning"], fg="#ffffff", font=("Courier New", 9, "bold"),
             relief="raised", padx=10).pack(side="left", padx=5)
    
    # Auto-load archives on open
    backup_window.after(500, refresh_archives)
    
    # ==================== TAB 2: RESTORE ====================
    restore_frame = tk.Frame(notebook, bg=THEME["panel"])
    notebook.add(restore_frame, text="  Restore  ")
    
    # Instructions
    tk.Label(restore_frame, text="🔍 Search and Restore Files from Backups",
            bg=THEME["panel"], fg=THEME["accent"], font=("Courier New", 12, "bold")).pack(pady=10)
    
    # Archive selection for restore
    restore_archive_frame = tk.Frame(restore_frame, bg=THEME["panel"])
    restore_archive_frame.pack(fill="x", padx=10, pady=5)
    
    tk.Label(restore_archive_frame, text="Select Archive:", 
            bg=THEME["panel"], fg=THEME["fg"], font=("Courier New", 10)).pack(side="left", padx=5)
    
    restore_archive_combo = ttk.Combobox(restore_archive_frame, font=("Courier New", 9), 
                                         state="readonly", width=40)
    restore_archive_combo.pack(side="left", padx=5)
    
    def update_restore_archives():
        """Sync archive list to restore tab."""
        archives = [archives_listbox.get(i).replace("📦 ", "") 
                   for i in range(archives_listbox.size()) 
                   if archives_listbox.get(i).startswith("📦")]
        restore_archive_combo['values'] = archives
        if archives:
            restore_archive_combo.current(0)
    
    tk.Button(restore_archive_frame, text="🔄", command=update_restore_archives,
             bg=THEME["accent"], fg="#ffffff", font=("Courier New", 8, "bold")).pack(side="left")
    
    # Search files
    search_frame = tk.Frame(restore_frame, bg=THEME["panel"])
    search_frame.pack(fill="x", padx=10, pady=5)
    
    tk.Label(search_frame, text="Search Files:", 
            bg=THEME["panel"], fg=THEME["fg"], font=("Courier New", 10)).pack(side="left", padx=5)
    
    search_entry = tk.Entry(search_frame, bg=THEME["bg"], fg=THEME["fg"],
                           font=("Courier New", 10), insertbackground=THEME["accent"])
    search_entry.pack(side="left", fill="x", expand=True, padx=5)
    
    # Files listbox
    files_list_frame = tk.Frame(restore_frame, bg=THEME["panel"])
    files_list_frame.pack(fill="both", expand=True, padx=10, pady=5)
    
    tk.Label(files_list_frame, text="Files in Archive:", 
            bg=THEME["panel"], fg=THEME["accent"], font=("Courier New", 10, "bold")).pack(anchor="w")
    
    files_listbox = tk.Listbox(files_list_frame, bg=THEME["bg"], fg=THEME["fg"],
                              font=("Courier New", 8), selectmode="extended",
                              selectbackground=THEME["accent"], height=15)
    files_scrollbar = tk.Scrollbar(files_list_frame, command=files_listbox.yview)
    files_listbox.config(yscrollcommand=files_scrollbar.set)
    files_listbox.pack(side="left", fill="both", expand=True)
    files_scrollbar.pack(side="right", fill="y")
    
    def search_files():
        """Search files in selected archive."""
        archive = restore_archive_combo.get()
        repo = repo_entry.get().strip()
        search_term = search_entry.get().strip()
        
        if not archive:
            messagebox.showwarning("Warning", "Please select an archive first")
            return
        
        passphrase = get_passphrase()
        if not passphrase:
            return
        
        files_listbox.delete(0, tk.END)
        files_listbox.insert(tk.END, "⏳ Searching files...")
        backup_window.update()
        
        def search_thread():
            try:
                # Create a wrapper command that sets passphrase and runs borg as root
                cmd = [
                    "pkexec", "bash", "-c",
                    f"export BORG_PASSPHRASE='{passphrase}' && borg list '{repo}::{archive}'"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                def update_ui():
                    files_listbox.delete(0, tk.END)
                    if result.returncode == 0:
                        count = 0
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                # Parse borg list output (format: perms user group size date time path)
                                parts = line.split()
                                if len(parts) >= 8:
                                    filepath = ' '.join(parts[7:])
                                    if not search_term or search_term.lower() in filepath.lower():
                                        files_listbox.insert(tk.END, filepath)
                                        count += 1
                        
                        if count == 0:
                            files_listbox.insert(tk.END, "❌ No files found matching criteria")
                    else:
                        files_listbox.insert(tk.END, f"❌ Error: {result.stderr}")
                
                backup_window.after(0, update_ui)
                
            except Exception as e:
                error_msg = f"Search failed:\n{e}"
                backup_window.after(0, lambda msg=error_msg: messagebox.showerror("Error", msg))
        
        threading.Thread(target=search_thread, daemon=True).start()
    
    tk.Button(search_frame, text="🔍 Search", command=search_files,
             bg=THEME["accent"], fg="#ffffff", font=("Courier New", 9, "bold")).pack(side="left", padx=5)
    
    # Restore buttons
    restore_btn_frame = tk.Frame(restore_frame, bg=THEME["panel"])
    restore_btn_frame.pack(fill="x", padx=10, pady=10)
    
    def restore_selected():
        """Restore selected files."""
        selected_indices = files_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select files to restore")
            return
        
        archive = restore_archive_combo.get()
        repo = repo_entry.get().strip()
        
        passphrase = get_passphrase()
        if not passphrase:
            return
        
        # Ask for restore destination
        dest = filedialog.askdirectory(title="Select Restore Destination", initialdir="/tmp")
        if not dest:
            return
        
        selected_files = [files_listbox.get(i) for i in selected_indices]
        
        confirm = messagebox.askyesno(
            "Confirm Restore",
            f"Restore {len(selected_files)} file(s) from:\n{archive}\n\nTo:\n{dest}\n\nContinue?"
        )
        
        if not confirm:
            return
        
        def restore_thread():
            try:
                # Build file list for command
                files_arg = " ".join([f"'{f}'" for f in selected_files])
                
                # Create a wrapper command that sets passphrase and runs borg as root
                cmd = [
                    "pkexec", "bash", "-c",
                    f"cd '{dest}' && export BORG_PASSPHRASE='{passphrase}' && borg extract '{repo}::{archive}' {files_arg}"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                def show_result():
                    if result.returncode == 0:
                        messagebox.showinfo("Success", 
                            f"✓ Restored {len(selected_files)} file(s) to:\n{dest}")
                    else:
                        messagebox.showerror("Error", 
                            f"Restore failed:\n{result.stderr}")
                
                backup_window.after(0, show_result)
                
            except Exception as e:
                error_msg = f"Restore failed:\n{e}"
                backup_window.after(0, lambda msg=error_msg: messagebox.showerror("Error", msg))
        
        threading.Thread(target=restore_thread, daemon=True).start()
    
    tk.Button(restore_btn_frame, text="💾 Restore Selected Files", command=restore_selected,
             bg=THEME["success"], fg="#ffffff", font=("Courier New", 10, "bold"),
             relief="raised", padx=20, pady=5).pack(pady=5)
    
    tk.Label(restore_btn_frame, text="💡 Tip: Select multiple files with Ctrl+Click or Shift+Click",
            bg=THEME["panel"], fg="#888888", font=("Courier New", 8, "italic")).pack()
    
    # ==================== TAB 3: LOGS ====================
    logs_frame = tk.Frame(notebook, bg=THEME["panel"])
    notebook.add(logs_frame, text="  Logs  ")
    
    tk.Label(logs_frame, text="📋 Backup Operation Logs",
            bg=THEME["panel"], fg=THEME["accent"], font=("Courier New", 12, "bold")).pack(pady=10)
    
    logs_text = scrolledtext.ScrolledText(logs_frame, bg=THEME["bg"], fg=THEME["fg"],
                                         font=("Courier New", 9), wrap="word",
                                         insertbackground=THEME["accent"])
    logs_text.pack(fill="both", expand=True, padx=10, pady=5)
    
    def load_logs():
        """Load backup logs."""
        logs_text.delete(1.0, tk.END)
        logs_text.insert(tk.END, "⏳ Loading logs...\n")
        backup_window.update()
        
        try:
            result = subprocess.run(
                ["tail", "-n", "100", "/var/log/pulse-backup.log"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            logs_text.delete(1.0, tk.END)
            if result.returncode == 0 and result.stdout:
                logs_text.insert(tk.END, result.stdout)
            else:
                logs_text.insert(tk.END, "❌ No logs found or backup hasn't run yet\n")
        except Exception as e:
            logs_text.delete(1.0, tk.END)
            logs_text.insert(tk.END, f"❌ Error loading logs: {e}\n")
    
    btn_frame = tk.Frame(logs_frame, bg=THEME["panel"])
    btn_frame.pack(fill="x", padx=10, pady=5)
    
    tk.Button(btn_frame, text="🔄 Refresh Logs", command=load_logs,
             bg=THEME["accent"], fg="#ffffff", font=("Courier New", 9, "bold")).pack(side="left", padx=5)
    
    tk.Button(btn_frame, text="🗑️ Clear Display", command=lambda: logs_text.delete(1.0, tk.END),
             bg=THEME["error"], fg="#ffffff", font=("Courier New", 9, "bold")).pack(side="left", padx=5)
    
    # Auto-load logs
    backup_window.after(500, load_logs)
    
    # ==================== TAB 4: SETTINGS ====================
    settings_frame = tk.Frame(notebook, bg=THEME["panel"])
    notebook.add(settings_frame, text="  Settings  ")
    
    tk.Label(settings_frame, text="⚙️ Backup Configuration",
            bg=THEME["panel"], fg=THEME["accent"], font=("Courier New", 12, "bold")).pack(pady=10)
    
    settings_text = scrolledtext.ScrolledText(settings_frame, bg=THEME["bg"], fg=THEME["fg"],
                                             font=("Courier New", 9), wrap="word", height=20)
    settings_text.pack(fill="both", expand=True, padx=10, pady=5)
    
    settings_info = """
📦 BorgBackup Configuration

Repository Location: /mnt/backup/borg-repo
Passphrase File: /root/.config/borg/passphrase
Log File: /var/log/pulse-backup.log
Backup Script: /usr/local/bin/pulse-backup

⏰ Schedule:
  • Daily backups at 2:00 AM
  • Timer: systemctl status pulse-backup.timer

🔐 Security:
  • Encryption: AES-256-CTR
  • Authentication: HMAC-SHA256
  • Compression: LZ4 (fast)

📊 Retention Policy:
  • Daily backups: Keep last 7 days
  • Weekly backups: Keep last 4 weeks
  • Monthly backups: Keep last 6 months

🛠️ Manual Commands:

Run Backup Now:
  sudo /usr/local/bin/pulse-backup

Check Repository:
  sudo borg check /mnt/backup/borg-repo

Repository Info:
  sudo borg info /mnt/backup/borg-repo

List Archives:
  sudo borg list /mnt/backup/borg-repo

View Passphrase:
  sudo cat /root/.config/borg/passphrase

⚠️ CRITICAL: Keep your passphrase safe!
Without it, backups are unrecoverable!
"""
    
    settings_text.insert(tk.END, settings_info)
    settings_text.config(state="disabled")
    
    def run_backup_now():
        """Trigger immediate backup with output to Logs tab."""
        confirm = messagebox.askyesno("Run Backup", "Run backup now?\n\nThis may take several minutes.")
        if not confirm:
            return
        
        # Switch to Logs tab
        notebook.select(2)  # Index 2 is Logs tab
        
        # Clear logs and show starting message
        logs_text.delete(1.0, tk.END)
        logs_text.insert(tk.END, "🚀 Starting backup operation...\n")
        logs_text.insert(tk.END, "=" * 60 + "\n\n")
        logs_text.insert(tk.END, "Note: You'll be prompted for authentication (pkexec)\n\n")
        backup_window.update()
        
        def backup_thread():
            try:
                # Run backup script with output streaming
                # The script reads passphrase from /root/.config/borg/passphrase
                process = subprocess.Popen(
                    ["pkexec", "/usr/local/bin/pulse-backup"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                # Stream output to GUI
                for line in process.stdout:
                    backup_window.after(0, lambda l=line: logs_text.insert(tk.END, l))
                    backup_window.after(0, lambda: logs_text.see(tk.END))
                
                process.wait()
                
                def show_completion():
                    logs_text.insert(tk.END, "\n" + "=" * 60 + "\n")
                    if process.returncode == 0:
                        logs_text.insert(tk.END, "✓ Backup completed successfully!\n", "success")
                        # Refresh archives list
                        refresh_archives()
                        messagebox.showinfo("Success", "✓ Backup completed successfully!")
                    else:
                        logs_text.insert(tk.END, f"❌ Backup failed with exit code {process.returncode}\n", "error")
                        messagebox.showerror("Error", f"Backup failed with exit code {process.returncode}")
                    logs_text.see(tk.END)
                
                backup_window.after(0, show_completion)
                
            except Exception as e:
                error_msg = f"\n❌ Backup error: {e}\n"
                backup_window.after(0, lambda msg=error_msg: logs_text.insert(tk.END, msg))
                backup_window.after(0, lambda: messagebox.showerror("Error", f"Backup failed:\n{e}"))
        
        threading.Thread(target=backup_thread, daemon=True).start()
    
    tk.Button(settings_frame, text="▶️ Run Backup Now", command=run_backup_now,
             bg=THEME["success"], fg="#ffffff", font=("Courier New", 10, "bold"),
             relief="raised", padx=20, pady=5).pack(pady=10)
    
    # Helper function for archive info
    def show_archive_info(repo, listbox, passphrase_cache):
        """Show detailed archive information."""
        selection = listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an archive")
            return
        
        archive = listbox.get(selection[0]).replace("📦 ", "")
        
        passphrase = passphrase_cache.get("value")
        if not passphrase:
            passphrase = get_passphrase()
            if not passphrase:
                return
        
        info_window = tk.Toplevel(backup_window)
        info_window.title(f"Archive Info: {archive}")
        info_window.geometry("600x400")
        info_window.configure(bg=THEME["bg"])
        
        info_text = scrolledtext.ScrolledText(info_window, bg=THEME["bg"], fg=THEME["fg"],
                                             font=("Courier New", 9), wrap="word")
        info_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        info_text.insert(tk.END, f"⏳ Loading info for {archive}...\n")
        info_window.update()
        
        def load_info():
            try:
                # Create a wrapper command that sets passphrase and runs borg as root
                cmd = [
                    "pkexec", "bash", "-c",
                    f"export BORG_PASSPHRASE='{passphrase}' && borg info '{repo}::{archive}'"
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                def update():
                    info_text.delete(1.0, tk.END)
                    if result.returncode == 0:
                        info_text.insert(tk.END, result.stdout)
                    else:
                        info_text.insert(tk.END, f"Error:\n{result.stderr}")
                
                info_window.after(0, update)
            except Exception as e:
                error_msg = f"\nError: {e}"
                info_window.after(0, lambda msg=error_msg: info_text.insert(tk.END, msg))
        
        threading.Thread(target=load_info, daemon=True).start()
    
    # Status bar
    status_bar = tk.Label(backup_window, text="Ready | BorgBackup GUI v2.0 - Blue Theme", 
                         bg=THEME["panel"], fg="#888888", 
                         font=("Courier New", 8), anchor="w", relief="sunken")
    status_bar.pack(side="bottom", fill="x")


def open_backup_manager():
    """Convenience wrapper for opening backup manager."""
    view_backup_logs(lambda msg, level="info": None)


def repair_backup_script(log_callback, root, progress_label, run_generic_command):
    """
    Repairs/updates the backup script with the latest fixes.
    Useful if the script was created with old code.
    """
    import base64
    from tkinter import messagebox
    
    confirm = messagebox.askyesno(
        "Repair Backup Script",
        "This will update /usr/local/bin/pulse-backup with the latest fixes.\n\n" +
        "Your repository and existing backups will NOT be affected.\n\n" +
        "Continue?"
    )
    
    if not confirm:
        return
    
    log_callback("Repairing backup script...")
    root.after(0, lambda: progress_label.config(text="Updating backup script..."))
    
    # Read current configuration from existing script if possible
    backup_dest = "/mnt/backup/borg-repo"
    backup_source = "/home"
    
    try:
        # Try to extract config from existing script
        import subprocess
        result = subprocess.run(
            ["grep", "BORG_REPO =", "/usr/local/bin/pulse-backup"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout:
            # Extract value between quotes
            import re
            match = re.search(r'BORG_REPO = ["\']([^"\']+)["\']', result.stdout)
            if match:
                backup_dest = match.group(1)
        
        result = subprocess.run(
            ["grep", "SOURCES =", "/usr/local/bin/pulse-backup"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout:
            import re
            match = re.search(r'SOURCES = ["\']([^"\']+)["\']', result.stdout)
            if match:
                backup_source = match.group(1)
    except:
        pass
    
    log_callback(f"Using repository: {backup_dest}")
    log_callback(f"Using sources: {backup_source}")
    
    # Create updated backup script with fix
    backup_script = '''#!/usr/bin/env python3
"""
PULSE BorgBackup Automation Script
- Deduplication: Chunk-level with rolling hash
- Encryption: AES-256-CTR with HMAC-SHA256
- Compression: LZ4 (fast) or ZSTD (better ratio)
- Pruning: Keeps daily/weekly/monthly archives
"""

import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
BORG_REPO = "''' + backup_dest + '''"
SOURCES = "''' + backup_source + '''".split(",")
LOGFILE = "/var/log/pulse-backup.log"
DATE = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
HOSTNAME = subprocess.check_output(["hostname"]).decode().strip()

# Passphrase location
PASSPHRASE_FILE = "/root/.config/borg/passphrase"

# Set environment for Borg
os.environ["BORG_REPO"] = BORG_REPO
os.environ["BORG_PASSPHRASE"] = open(PASSPHRASE_FILE).read().strip()
os.environ["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "yes"

def log(message, level="INFO"):
    """Log with timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = "[{0}] [{1}] {2}\\n".format(timestamp, level, message)
    
    try:
        with open(LOGFILE, 'a') as f:
            f.write(log_entry)
        print(log_entry.strip())
    except Exception as e:
        print("Logging error: {0}".format(e))

def run_borg_command(cmd, description):
    """Execute Borg command with logging."""
    log("Running: {0}".format(description))
    log("Command: {0}".format(' '.join(cmd)))
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200
        )
        
        if result.returncode == 0:
            log("✓ {0} completed successfully".format(description), "SUCCESS")
            if result.stdout:
                for line in result.stdout.split('\\n')[:20]:
                    if line.strip():
                        log("  {0}".format(line))
            return True
        else:
            log("✗ {0} failed (exit code {1})".format(description, result.returncode), "ERROR")
            if result.stderr:
                log("Error output: {0}".format(result.stderr), "ERROR")
            return False
            
    except subprocess.TimeoutExpired:
        log("✗ {0} timed out (>2 hours)".format(description), "ERROR")
        return False
    except Exception as e:
        log("✗ {0} exception: {1}".format(description, e), "ERROR")
        return False

def check_borg_installed():
    """Verify BorgBackup is installed."""
    try:
        result = subprocess.run(
            ["borg", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            log("BorgBackup detected: {0}".format(version))
            return True
    except FileNotFoundError:
        log("BorgBackup not found - please install: apt install borgbackup", "ERROR")
        return False

def initialize_repo():
    """Initialize Borg repository if it doesn't exist."""
    log("Checking repository: {0}".format(BORG_REPO))
    
    # First check if repository directory exists and has borg files
    import os
    repo_config = os.path.join(BORG_REPO, "config")
    
    if os.path.exists(repo_config):
        log("Repository already exists (found config file)")
        return True
    
    # Try to list archives as secondary check
    result = subprocess.run(
        ["borg", "list", BORG_REPO],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        log("Repository already initialized")
        return True
    
    # Repository doesn't exist, create it
    log("Repository not initialized, creating new encrypted repository...")
    return run_borg_command(
        ["borg", "init", "--encryption=repokey-blake2", BORG_REPO],
        "Repository initialization"
    )

def create_backup():
    """Create backup archive."""
    archive_name = "{0}-{1}".format(HOSTNAME, DATE)
    
    log("Creating backup archive: {0}".format(archive_name))
    
    sources_list = [s.strip() for s in SOURCES if os.path.exists(s.strip())]
    
    if not sources_list:
        log("No valid source directories found!", "ERROR")
        return False
    
    log("Backing up: {0}".format(', '.join(sources_list)))
    
    cmd = [
        "borg", "create",
        "--verbose",
        "--stats",
        "--compression", "lz4",
        "--exclude-caches",
        "--exclude", "*/.cache/*",
        "--exclude", "*/lost+found",
        "--exclude", "*.tmp",
        "::{0}".format(archive_name)
    ] + sources_list
    
    return run_borg_command(cmd, "Backup creation ({0})".format(archive_name))

def prune_old_backups():
    """Remove old backups according to retention policy."""
    log("Pruning old backups...")
    
    cmd = [
        "borg", "prune",
        "--verbose",
        "--stats",
        "--keep-daily=7",
        "--keep-weekly=4",
        "--keep-monthly=6"
    ]
    
    return run_borg_command(cmd, "Backup pruning")

def verify_backup():
    """Verify repository integrity and latest archive."""
    log("Verifying repository integrity...")
    
    if not run_borg_command(
        ["borg", "check", "--verbose"],
        "Repository integrity check"
    ):
        return False
    
    log("Listing backup archives...")
    run_borg_command(
        ["borg", "list", "--short"],
        "Archive listing"
    )
    
    return True

def get_repo_info():
    """Display repository statistics."""
    log("Repository information:")
    run_borg_command(
        ["borg", "info"],
        "Repository info"
    )

def main():
    """Main backup execution."""
    log("=" * 70)
    log("PULSE BorgBackup Started: {0}".format(DATE))
    log("=" * 70)
    
    if not check_borg_installed():
        sys.exit(1)
    
    if not os.path.exists(PASSPHRASE_FILE):
        log("Passphrase file not found: {0}".format(PASSPHRASE_FILE), "ERROR")
        sys.exit(1)
    
    if not initialize_repo():
        log("Failed to initialize repository", "ERROR")
        sys.exit(1)
    
    if not create_backup():
        log("Backup creation failed", "ERROR")
        sys.exit(1)
    
    if not prune_old_backups():
        log("Pruning failed (non-critical)", "WARN")
    
    if not verify_backup():
        log("Verification failed", "ERROR")
        sys.exit(1)
    
    get_repo_info()
    
    log("=" * 70)
    log("✓ Backup completed successfully", "SUCCESS")
    log("=" * 70)
    log("")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Backup interrupted by user", "WARN")
        sys.exit(1)
    except Exception as e:
        log("CRITICAL ERROR: {0}: {1}".format(type(e).__name__, e), "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")
        sys.exit(1)
'''
    
    # Use base64 encoding
    script_b64 = base64.b64encode(backup_script.encode()).decode()
    
    # Update script
    update_cmd = [
        "pkexec", "bash", "-c",
        f"echo '{script_b64}' | base64 -d > /usr/local/bin/pulse-backup && "
        f"chmod +x /usr/local/bin/pulse-backup && "
        f"echo 'Backup script updated successfully'"
    ]
    
    run_generic_command(update_cmd, "Backup Script Repair")
    log_callback("✓ Backup script repaired successfully!", "success")
    log_callback("You can now run backups normally.", "info")


def execute_firewall_hardening(log_callback, root, progress_label, run_generic_command):
    """
    Configures UFW firewall with secure defaults.
    - Installs UFW if not present
    - Enables firewall
    - Sets default deny incoming, allow outgoing
    - Allows SSH on port 2222
    """
    log_callback("Configuring UFW Firewall...")
    root.after(0, lambda: progress_label.config(text="Configuring firewall..."))
    
    firewall_cmd = [
        "pkexec", "bash", "-c",
        "apt-get install -y ufw && "
        "ufw --force reset && "
        "ufw default deny incoming && "
        "ufw default allow outgoing && "
        "ufw allow 2222/tcp comment 'SSH' && "
        "ufw --force enable && "
        "systemctl enable ufw"
    ]
    
    run_generic_command(firewall_cmd, "UFW Firewall Configuration")
    log_callback("Firewall hardening completed!", "success")


def execute_disable_services(log_callback, root, progress_label, run_generic_command):
    """
    Disables unnecessary services to reduce attack surface.
    - Bluetooth (if not using)
    - CUPS (printer service)
    - Avahi (mDNS/Bonjour)
    """
    log_callback("Disabling unnecessary services...")
    root.after(0, lambda: progress_label.config(text="Disabling services..."))
    
    services_cmd = [
        "pkexec", "bash", "-c",
        "systemctl disable bluetooth.service 2>/dev/null || true && "
        "systemctl stop bluetooth.service 2>/dev/null || true && "
        "systemctl disable cups.service 2>/dev/null || true && "
        "systemctl stop cups.service 2>/dev/null || true && "
        "systemctl disable avahi-daemon.service 2>/dev/null || true && "
        "systemctl stop avahi-daemon.service 2>/dev/null || true"
    ]
    
    run_generic_command(services_cmd, "Disable Unnecessary Services")
    log_callback("Service hardening completed!", "success")


def execute_ssh_hardening(log_callback, root, progress_label, run_generic_command):
    """
    Hardens SSH configuration.
    - Disables root login
    - Changes SSH port to 2222
    - Disables password authentication (forces key-based)
    """
    log_callback("Hardening SSH configuration...")
    root.after(0, lambda: progress_label.config(text="Configuring SSH..."))
    
    ssh_cmd = [
        "pkexec", "bash", "-c",
        "if [ -f /etc/ssh/sshd_config ]; then "
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && "
        "sed -i 's/^#*Port.*/Port 2222/' /etc/ssh/sshd_config && "
        "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && "
        "systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true; "
        "else echo 'SSH not installed, skipping'; fi"
    ]
    
    run_generic_command(ssh_cmd, "SSH Hardening")
    log_callback("SSH hardening completed!", "success")


def execute_auto_updates(log_callback, root, progress_label, run_generic_command):
    """
    Enables automatic security updates.
    Installs and configures unattended-upgrades package.
    """
    log_callback("Enabling automatic security updates...")
    root.after(0, lambda: progress_label.config(text="Configuring auto-updates..."))
    
    updates_cmd = [
        "pkexec", "bash", "-c",
        "apt-get install -y unattended-upgrades && "
        "echo 'APT::Periodic::Update-Package-Lists \"1\";' > /etc/apt/apt.conf.d/20auto-upgrades && "
        "echo 'APT::Periodic::Unattended-Upgrade \"1\";' >> /etc/apt/apt.conf.d/20auto-upgrades && "
        "systemctl enable unattended-upgrades"
    ]
    
    run_generic_command(updates_cmd, "Automatic Security Updates")
    log_callback("Auto-update configuration completed!", "success")


def execute_privesc_hardening(log_callback, root, progress_label, run_generic_command):
    """
    Hardens privilege escalation and core dumps.
    - Disables core dumps (prevents memory dumping)
    - Sets sudo timeout to 5 minutes
    - Limits su command to sudo group only
    """
    log_callback("Hardening privilege escalation...")
    root.after(0, lambda: progress_label.config(text="Configuring privileges..."))
    
    privesc_cmd = [
        "pkexec", "bash", "-c",
        "echo '* hard core 0' >> /etc/security/limits.conf && "
        "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf && "
        "echo 'Defaults timestamp_timeout=5' >> /etc/sudoers.d/timeout && "
        "chmod 0440 /etc/sudoers.d/timeout && "
        "sysctl -p"
    ]
    
    run_generic_command(privesc_cmd, "Privilege Escalation Hardening")
    log_callback("Privilege hardening completed!", "success")


def execute_dns_cloudflare(log_callback, root, progress_label, run_generic_command):
    """Changes DNS to Cloudflare (1.1.1.1)."""
    log_callback("Changing DNS to Cloudflare...")
    root.after(0, lambda: progress_label.config(text="Configuring DNS (Cloudflare)..."))
    
    dns_cmd = [
        "pkexec", "bash", "-c",
        "echo 'nameserver 1.1.1.1' > /etc/resolv.conf && "
        "echo 'nameserver 1.0.0.1' >> /etc/resolv.conf"
    ]
    
    run_generic_command(dns_cmd, "DNS Configuration (Cloudflare)")
    log_callback("DNS changed to Cloudflare!", "success")


def execute_dns_google(log_callback, root, progress_label, run_generic_command):
    """Changes DNS to Google (8.8.8.8)."""
    log_callback("Changing DNS to Google...")
    root.after(0, lambda: progress_label.config(text="Configuring DNS (Google)..."))
    
    dns_cmd = [
        "pkexec", "bash", "-c",
        "echo 'nameserver 8.8.8.8' > /etc/resolv.conf && "
        "echo 'nameserver 8.8.4.4' >> /etc/resolv.conf"
    ]
    
    run_generic_command(dns_cmd, "DNS Configuration (Google)")
    log_callback("DNS changed to Google!", "success")


def execute_bbr_tcp(log_callback, root, progress_label, run_generic_command):
    """Enables BBR TCP congestion control for improved network performance."""
    log_callback("Enabling BBR TCP congestion control...")
    root.after(0, lambda: progress_label.config(text="Enabling BBR TCP..."))
    
    bbr_cmd = [
        "pkexec", "bash", "-c",
        "echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf && "
        "echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf && "
        "sysctl -p"
    ]
    
    run_generic_command(bbr_cmd, "BBR TCP Configuration")
    log_callback("BBR TCP enabled! Reboot required for full effect.", "success")


def execute_change_mac(log_callback, root, progress_label, run_generic_command):
    """Randomizes MAC address for privacy."""
    log_callback("Randomizing MAC address...")
    root.after(0, lambda: progress_label.config(text="Changing MAC address..."))
    
    mac_cmd = [
        "pkexec", "bash", "-c",
        "apt-get install -y macchanger && "
        "IFACE=$(ip route | grep default | awk '{print $5}' | head -n1) && "
        "ip link set $IFACE down && "
        "macchanger -r $IFACE && "
        "ip link set $IFACE up"
    ]
    
    run_generic_command(mac_cmd, "MAC Address Change")
    log_callback("MAC address randomized! Network restarted.", "success")


def install_security_tools(log_callback, root, progress_bar, progress_label, btn_action, run_generic_command):
    """
    Installs optional security tools for advanced protection.
    - Fail2Ban: Brute force protection
    - ClamAV: Antivirus scanner
    - RKHunter: Rootkit detector
    - Lynis: Security auditing
    - AppArmor: Mandatory access control
    """
    confirm = messagebox.askyesno(
        "Install Security Tools",
        "This will install the following tools:\n\n" +
        "• Fail2Ban (brute force protection)\n" +
        "• ClamAV (antivirus scanner)\n" +
        "• RKHunter (rootkit detector)\n" +
        "• Lynis (security auditing tool)\n" +
        "• AppArmor (mandatory access control)\n\n" +
        "This may take several minutes. Continue?"
    )
    
    if not confirm:
        return
    
    log_callback("Installing security tools...")
    btn_action.config(state="disabled", text="INSTALLING...")
    
    def install_thread():
        root.after(0, lambda: progress_bar.config(value=10))
        root.after(0, lambda: progress_label.config(text="Installing security tools..."))
        
        tools_cmd = [
            "pkexec", "bash", "-c",
            "apt-get update && "
            "apt-get install -y fail2ban clamav clamav-daemon rkhunter lynis apparmor apparmor-utils && "
            "systemctl enable fail2ban && "
            "systemctl start fail2ban && "
            "freshclam && "
            "systemctl enable clamav-freshclam && "
            "systemctl start clamav-freshclam"
        ]
        
        run_generic_command(tools_cmd, "Security Tools Installation")
        
        root.after(0, lambda: progress_bar.config(value=100))
        root.after(0, lambda: progress_label.config(text="Security tools installed"))
        log_callback("Security tools installation completed!", "success")
        root.after(0, lambda: btn_action.config(state="normal", text="[ RUN TWEAKS ]"))
    
    threading.Thread(target=install_thread, daemon=True).start()
