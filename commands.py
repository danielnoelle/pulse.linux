#!/usr/bin/env python3
import subprocess
import os
import shutil
from tkinter import messagebox


def run_apt_install(package_list, log_callback, root, progress_bar, progress_label, refresh_callback, clear_checkboxes_callback, btn_action):
    """
    Executes the batch installation command with progress tracking.
    Uses pkexec for privilege escalation (GUI password prompt).
    All packages are installed in a single command to minimize auth prompts.
    
    Args:
        package_list: List of package names to install (validated)
        log_callback: Function to log messages
        root: Tkinter root for thread-safe GUI updates
        progress_bar: Progress bar widget
        progress_label: Progress label widget
        refresh_callback: Function to refresh installed apps
        clear_checkboxes_callback: Function to clear checkbox selections
        btn_action: Action button widget
        
    Process:
    1. Updates progress bar to show operation start
    2. Constructs single apt-get command with all packages
    3. Executes command via run_generic_command
    4. Re-enables UI controls after completion
    
    Benefits of Batch Installation:
    - Single authentication prompt for all packages
    - Faster overall installation time
    - Better dependency resolution
    - Unified transaction (all-or-nothing for dependencies)
    
    Note: Progress bar shows approximate progress. Actual installation
    progress depends on package sizes and download speeds.
    """
    total = len(package_list)
    log_callback(f"Starting batch installation for {total} packages.")
    log_callback(f"Packages: {', '.join(package_list)}")
    
    # Update progress bar (10% to indicate start)
    root.after(0, lambda: progress_bar.config(value=10))
    root.after(0, lambda: progress_label.config(
        text=f"Installing {total} packages... (This may take several minutes)"
    ))
    
    # Construct single apt-get command with all packages
    # -y flag: automatic yes to prompts (non-interactive)
    cmd = ["pkexec", "apt-get", "install", "-y"] + package_list
    
    # Execute and handle result (run_generic_command handles errors)
    # This call blocks until completion (running in background thread)
    run_generic_command(cmd, f"Batch Install ({total} packages)", log_callback, root, refresh_callback)
    
    # Clear selections after installation
    root.after(0, clear_checkboxes_callback)
    
    # Reset progress bar and re-enable action button
    root.after(0, lambda: progress_bar.config(value=100))
    root.after(0, lambda: btn_action.config(state="normal", text="[ INSTALL ]"))


def install_deb_package(deb_source, log_callback, refresh_callback):
    """Install .deb package from URL or local path."""
    log_callback(f"Installing .deb package...")
    
    try:
        # If URL, download first
        if deb_source.startswith("http://") or deb_source.startswith("https://"):
            log_callback(f"Downloading from {deb_source}...")
            
            # Download to /tmp
            filename = deb_source.split("/")[-1]
            local_path = f"/tmp/{filename}"
            
            download_result = subprocess.run(
                ["wget", "-O", local_path, deb_source],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if download_result.returncode != 0:
                log_callback(f"✗ Download failed: {download_result.stderr}", "error")
                return
            
            log_callback(f"✓ Downloaded to {local_path}", "success")
            deb_path = local_path
        else:
            # Local file
            if not os.path.exists(deb_source):
                log_callback(f"✗ File not found: {deb_source}", "error")
                return
            deb_path = deb_source
        
        # Install with dpkg
        log_callback(f"Installing {deb_path}...")
        
        # Extract package name from filename
        pkg_filename = os.path.basename(deb_path)
        pkg_name = pkg_filename.split("_")[0] if "_" in pkg_filename else pkg_filename.replace(".deb", "")
        
        install_result = subprocess.run(
            ["pkexec", "dpkg", "-i", deb_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if install_result.returncode == 0:
            log_callback(f"✓ Package '{pkg_name}' installed successfully!", "success")
            
            # Fix dependencies if needed
            log_callback("Fixing dependencies with apt-get install -f...")
            subprocess.run(
                ["pkexec", "apt-get", "install", "-f", "-y"],
                capture_output=True,
                timeout=120
            )
            
            log_callback(f"✓ {pkg_name} is now installed and ready to use", "success")
            refresh_callback()
        else:
            log_callback(f"✗ Installation failed: {install_result.stderr}", "error")
            
    except subprocess.TimeoutExpired:
        log_callback("✗ Installation timed out", "error")
    except Exception as e:
        log_callback(f"✗ Installation error: {e}", "error")


def run_generic_command(cmd, description, log_callback, root, refresh_callback=None):
    """
    Run subprocess command with real-time output streaming and comprehensive error handling.
    Auto-refreshes package cache on successful APT operations.
    
    Args:
        cmd: Command list to execute
        description: Human-readable description of the command
        log_callback: Function to log messages (signature: log_callback(msg, type))
        root: Tkinter root for thread-safe GUI updates
        refresh_callback: Optional function to refresh installed apps after APT operations
    """
    # Input validation
    if not cmd or not isinstance(cmd, list):
        error_msg = "Invalid command: must be a non-empty list"
        log_callback(error_msg, "error")
        root.after(0, lambda: messagebox.showerror("Invalid Command", error_msg))
        return
    
    if not description or not isinstance(description, str):
        description = "Unnamed Command"
    
    # Security: validate no empty arguments
    if any(arg == '' for arg in cmd):
        error_msg = "Command contains empty arguments - potential security risk"
        log_callback(error_msg, "error")
        return
    
    log_callback(f"Executing: {' '.join(cmd)}")
    
    try:
        # Execute with merged stdout/stderr
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Stream output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                log_callback(f"CMD > {output.strip()}")
        
        process.stdout.close()
        return_code = process.wait()
        
        # Check exit code
        if return_code == 0:
            log_callback(f"Finished: {description}", "success")
            root.after(0, lambda: messagebox.showinfo("Success", f"{description} completed."))
            
            # Refresh cache after successful APT operations
            if refresh_callback and len(cmd) > 1 and 'apt' in cmd[1].lower():
                import threading
                threading.Thread(target=refresh_callback, daemon=True).start()
        else:
            log_callback(f"Failed: {description} (Exit Code: {return_code})", "error")
            root.after(0, lambda rc=return_code: messagebox.showerror(
                "Error", f"{description} failed.\nExit Code: {rc}\n\nCheck logs for details."))
            
    except FileNotFoundError:
        error_msg = f"Command not found: {cmd[0]}\n\nIs it installed?\nTry: sudo apt install {cmd[0]}"
        log_callback(error_msg, "error")
        root.after(0, lambda: messagebox.showerror("Command Not Found", error_msg))
        
    except PermissionError as e:
        error_msg = f"Permission denied: {e}\n\nThis operation requires elevated privileges."
        log_callback(error_msg, "error")
        root.after(0, lambda: messagebox.showerror("Permission Error", error_msg))
        
    except OSError as e:
        error_msg = f"System Error: {e}\n\nPossible causes: disk full, resource exhaustion"
        log_callback(error_msg, "error")
        root.after(0, lambda: messagebox.showerror("System Error", error_msg))
        
    except Exception as e:
        error_msg = f"Execution Error: {type(e).__name__}: {e}"
        log_callback(error_msg, "error")
        root.after(0, lambda: messagebox.showerror("Error", error_msg))
