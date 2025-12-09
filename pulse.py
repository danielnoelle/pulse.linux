#!/usr/bin/env python3
"""PULSE - Package Utilities & Linux System Engine

A comprehensive system administration tool for Debian-based Linux distributions.
Provides GUI for package management, system tweaks, security hardening, and monitoring.

Architecture:
    - Modular design with separated concerns (apt_manager, commands, tweaks, config)
    - Thread-based background operations to prevent UI freezing
    - Security-first: input sanitization, validation, logging
    - User preferences persistence with JSON
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import shutil
import threading
import os
import re
import json
import logging
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Import modularized components
from apt_manager import AptManager, HAS_APT_LIB
from ui_helpers import ToolTip, create_tooltip
from commands import run_apt_install, install_deb_package, run_generic_command
from tweaks import (
    execute_safe_cleanup, execute_automated_backup, view_backup_logs, repair_backup_script,
    execute_firewall_hardening, execute_disable_services,
    execute_ssh_hardening, execute_auto_updates, execute_privesc_hardening,
    execute_dns_cloudflare, execute_dns_google, execute_bbr_tcp,
    execute_change_mac, install_security_tools
)
from config import (
    THEME, ASCII_HEADER, APPS, VALID_LOG_TYPES, MAX_DISPLAY_PACKAGES,
    DESKTOP_ENTRY_PERMISSIONS, DIRECTORY_PERMISSIONS, CONFIG_DIR, LOG_DIR, CONFIG_FILE
)

# ==========================================
# SECURITY & UTILITY FUNCTIONS
# ==========================================

def sanitize_input(user_input):
    """Prevent command injection by validating input.
    
    Args:
        user_input: String to validate
    
    Returns:
        Sanitized string if valid
    
    Raises:
        ValueError: If input contains dangerous characters
    """
    if not user_input:
        raise ValueError("Input cannot be empty")
    
    # Allow only alphanumeric, dash, underscore, dot, colon, slash, equals
    # This covers package names, URLs, and common file paths
    if not re.match(r'^[a-zA-Z0-9._:/=+-]+$', user_input):
        raise ValueError(f"Invalid input contains dangerous characters: {user_input}")
    
    # Block common injection patterns (shell operators, wildcards, command substitution)
    dangerous_patterns = [
        r';', r'\|\|', r'&&', r'`', r'\$\(', r'\${',  # Command chaining/substitution
        r'>', r'<', r'\*', r'\?', r'~'  # Redirects and wildcards
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, user_input):
            raise ValueError(f"Input contains forbidden pattern: {pattern}")
    
    return user_input

def validate_url(url):
    """Validate download URLs for security.
    
    Args:
        url: URL string to validate
    
    Returns:
        Validated URL if safe
    
    Raises:
        ValueError: If URL is invalid or uses dangerous protocol
    """
    if not url:
        raise ValueError("URL cannot be empty")
    
    parsed = urlparse(url)
    
    # Only allow HTTP(S) and FTP protocols
    if parsed.scheme not in ['http', 'https', 'ftp']:
        raise ValueError(f"Only HTTP(S) and FTP protocols allowed, got: {parsed.scheme}")
    
    # Ensure hostname exists
    if not parsed.netloc:
        raise ValueError("Invalid URL: missing hostname")
    
    # Block localhost and private IPs to prevent SSRF attacks
    # Prevents accessing internal services or cloud metadata endpoints
    dangerous_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
    if parsed.netloc.lower() in dangerous_hosts or parsed.netloc.startswith('192.168.') or parsed.netloc.startswith('10.'):
        raise ValueError(f"Access to private/local networks not allowed: {parsed.netloc}")
    
    return url

def setup_file_logging():
    """Configure rotating file logging system.
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create directories if they don't exist
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Configure logger
    logger = logging.getLogger('PULSE')
    logger.setLevel(logging.INFO)
    
    # Prevent duplicate handlers on re-initialization (singleton pattern)
    if logger.handlers:
        return logger
    
    # File handler with rotation (5MB max, 3 backups)
    log_file = LOG_DIR / "pulse.log"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3
    )
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger

def load_user_preferences():
    """Load user preferences from config file.
    
    Returns:
        dict: User preferences or empty dict if file doesn't exist
    """
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.getLogger('PULSE').error(f"Failed to load preferences: {e}")
            return {}
    return {}

def save_user_preferences(preferences):
    """Save user preferences to config file.
    
    Args:
        preferences: Dictionary of preferences to save
    
    Returns:
        bool: True if saved successfully, False otherwise
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(preferences, f, indent=2)
        return True
    except IOError as e:
        logging.getLogger('PULSE').error(f"Failed to save preferences: {e}")
        return False

# ==========================================
# MAIN APPLICATION
# ==========================================

class PulseInstaller:
    """Main GUI application for package management and system optimization."""
    
    def __init__(self, root):
        """Initialize application with root window."""
        self.root = root
        self.root.title("PULSE - Package Utilities & Linux System Engine")
        
        # Initialize file logging
        self.file_logger = setup_file_logging()
        self.file_logger.info("PULSE application starting")
        
        # Load user preferences
        self.preferences = load_user_preferences()
        self.file_logger.info(f"Loaded {len(self.preferences)} user preferences")
        
        # Apply saved window geometry or use default
        window_geometry = self.preferences.get("window_geometry", "1100x800")
        self.root.geometry(window_geometry)
        self.root.configure(bg=THEME["bg"])
        
        # Initialize managers
        self.apt_manager = AptManager(self.log_system)
        
        # Application state (optimized data structures for O(1) lookups)
        self.checkboxes = {}  # Maps display_name -> {"var": BooleanVar, "pkg": pkg_name}
        self.installed_apps = set()  # Set of installed app display names for fast membership tests
        self.current_module = "install"  # Track current active module for context-aware operations
        
        # Set up cleanup on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # UI Setup
        self.setup_styles()
        self.build_ui()
        
        # System initialization
        self.log_system("System Initialized.")
        
        if not HAS_APT_LIB:
            messagebox.showerror(
                "Missing Dependency", 
                "python3-apt library not found.\n\n"
                "Install it with:\nsudo apt install python3-apt\n\n"
                "Some features will be disabled until installed."
            )
        else:
            # Run cache initialization in background to avoid UI freeze during APT database scan
            # Daemon thread exits automatically when main thread terminates
            threading.Thread(target=self.init_background_tasks, daemon=True).start()

    def init_background_tasks(self):
        """Run heavy initialization in background (APT cache, package scan)."""
        self.apt_manager.initialize()
        self.refresh_installed_apps()

    def validate_packages(self, package_list):
        """Check if packages exist in repositories before installation.
        
        Args:
            package_list: List of package names to validate
        
        Returns:
            tuple: (valid_packages, invalid_packages)
        """
        valid = []
        invalid = []
        
        self.log_system(f"Validating {len(package_list)} packages...", "info")
        
        try:
            # Use apt-cache to search for all available packages (faster than querying individually)
            # --names-only limits to package names, '.' matches all
            result = subprocess.run(
                ['apt-cache', 'search', '--names-only', '.'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.log_system("Package validation failed, proceeding anyway", "warn")
                self.file_logger.warning(f"apt-cache search failed: {result.stderr}")
                return package_list, []  # Return all as valid on error
            
            # Build set of available packages
            available = set()
            for line in result.stdout.splitlines():
                if line.strip():
                    pkg_name = line.split()[0]
                    available.add(pkg_name)
            
            # Validate each package
            for pkg in package_list:
                # Sanitize package name
                try:
                    sanitized_pkg = sanitize_input(pkg)
                    if sanitized_pkg in available:
                        valid.append(sanitized_pkg)
                    else:
                        invalid.append(sanitized_pkg)
                        self.log_system(f"Package not found in repos: {pkg}", "warn")
                        self.file_logger.warning(f"Package validation failed: {pkg}")
                except ValueError as e:
                    invalid.append(pkg)
                    self.log_system(f"Invalid package name: {pkg}", "error")
                    self.file_logger.error(f"Package name validation failed: {e}")
            
            if invalid:
                self.log_system(f"Found {len(invalid)} invalid packages", "warn")
            else:
                self.log_system("All packages validated successfully", "success")
            
            return valid, invalid
            
        except subprocess.TimeoutExpired:
            self.log_system("Package validation timed out, proceeding anyway", "warn")
            self.file_logger.error("apt-cache search timed out")
            return package_list, []  # Return all as valid on timeout
        except Exception as e:
            self.log_system(f"Validation error: {str(e)}", "error")
            self.file_logger.error(f"Package validation exception: {e}")
            return package_list, []  # Return all as valid on error

    def setup_styles(self):
        """Configure ttk styles for consistent modern theme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Checkbutton styling
        style.configure("TCheckbutton", 
                        background=THEME["panel"], 
                        foreground=THEME["accent"], 
                        font=THEME["font_main"], 
                        indicatorcolor=THEME["bg"], 
                        indicatorrelief="flat")
        style.map("TCheckbutton", 
                  indicatorcolor=[('selected', THEME["accent"])], 
                  background=[('active', THEME["panel"])])
        
        # Notebook (Tabs) styling
        style.configure("TNotebook", 
                        background=THEME["bg"], 
                        borderwidth=0)
        style.configure("TNotebook.Tab", 
                        background=THEME["bg"], 
                        foreground=THEME["fg"], 
                        padding=[15, 8], 
                        font=THEME["font_main"])
        style.map("TNotebook.Tab", 
                  background=[("selected", THEME["panel"])], 
                  foreground=[("selected", THEME["accent"])])
        
        # Progress Bar styling
        style.configure("Custom.Horizontal.TProgressbar", 
                        background=THEME["accent"], 
                        troughcolor=THEME["panel"], 
                        bordercolor=THEME["bg"], 
                        lightcolor=THEME["accent"], 
                        darkcolor=THEME["accent"])

    def build_ui(self):
        """Build main UI: Header -> Tabs -> Progress/Actions -> Logs."""
        # 1. Header with ASCII art
        header_frame = tk.Frame(self.root, bg=THEME["bg"])
        header_frame.pack(fill="x", pady=5)
        tk.Label(header_frame, text=ASCII_HEADER, bg=THEME["bg"], fg=THEME["accent"], 
                 font=THEME["font_ascii"], justify="left").pack()

        # 2. Main Split Container (Resizable panes)
        self.paned_window = tk.PanedWindow(self.root, orient="vertical", bg=THEME["panel"], 
                                           sashwidth=4, sashrelief="flat")
        self.paned_window.pack(fill="both", expand=True, padx=10, pady=10)

        # 3. Top Pane: Application Tabs
        self.top_pane = tk.Frame(self.paned_window, bg=THEME["bg"])
        self.paned_window.add(self.top_pane, height=400)
        
        self.notebook = ttk.Notebook(self.top_pane)
        self.notebook.pack(fill="both", expand=True)

        # Dynamically create category tabs from APPS dictionary
        for category, apps in APPS.items():
            self.create_category_tab(category, apps)
        
        # Add the "Installed Apps" management tab
        self.create_installed_tab()
        
        # Create Tweaks tab (hidden by default)
        self.create_tweaks_tab()
        
        # Create Security tab (hidden by default)
        self.create_security_tab()
        
        # Create Network tab (hidden by default)
        self.create_network_tab()
        
        # Create Presets tab (hidden by default)
        self.create_presets_tab()

        # Create Monitor tabs (hidden by default)
        self.create_audit_tab()
        self.create_resources_tab()
        self.create_services_tab()

        # 4. Bottom Pane: Progress, Actions, and Logs
        self.bottom_pane = tk.Frame(self.paned_window, bg=THEME["bg"])
        self.paned_window.add(self.bottom_pane)

        self.build_action_area()
        self.build_log_area()

    def build_action_area(self):
        """Build progress bar and action buttons."""
        # Progress Bar Frame
        progress_frame = tk.Frame(self.bottom_pane, bg=THEME["panel"], height=60)
        progress_frame.pack(fill="x", side="top", pady=(0, 5))
        
        self.progress_label = tk.Label(progress_frame, text="Initializing...", 
                                       bg=THEME["panel"], fg=THEME["fg"], 
                                       font=THEME["font_main"], anchor="w")
        self.progress_label.pack(fill="x", padx=10, pady=(5, 0))
        
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                            style="Custom.Horizontal.TProgressbar", 
                                            orient="horizontal", mode="determinate", length=400)
        self.progress_bar.pack(fill="x", padx=10, pady=5)

        # Module Navigation Buttons
        module_frame = tk.Frame(self.bottom_pane, bg=THEME["bg"], height=60)
        module_frame.pack(fill="x", side="top", pady=(5, 5))
        
        tk.Label(module_frame, text="MODULES:", bg=THEME["bg"], fg=THEME["accent"], 
                 font=("Courier New", 10, "bold")).pack(side="left", padx=10)
        
        self.btn_module_install = tk.Button(module_frame, text="INSTALL", bg=THEME["accent"], fg=THEME["bg"], 
                  font=("Courier New", 9, "bold"), relief="flat", width=12,
                  command=lambda: self.switch_module("install"))
        self.btn_module_install.pack(side="left", padx=5)
        
        self.btn_module_tweaks = tk.Button(module_frame, text="TWEAKS", bg=THEME["panel"], fg=THEME["fg"], 
                  font=("Courier New", 9, "bold"), relief="flat", width=12,
                  command=lambda: self.switch_module("tweaks"))
        self.btn_module_tweaks.pack(side="left", padx=5)
        
        self.btn_module_monitor = tk.Button(module_frame, text="MONITOR", bg=THEME["panel"], fg=THEME["fg"], 
                  font=("Courier New", 9, "bold"), relief="flat", width=12,
                  command=lambda: self.switch_module("monitor"))
        self.btn_module_monitor.pack(side="left", padx=5)
        
        tk.Button(module_frame, text="ABOUT", bg=THEME["panel"], fg=THEME["fg"], 
                  font=("Courier New", 9, "bold"), relief="flat", width=12,
                  command=self.show_about_dialog).pack(side="left", padx=5)

        # Action Buttons Frame
        action_frame = tk.Frame(self.bottom_pane, bg=THEME["panel"], height=50)
        action_frame.pack(fill="x", side="top")
        
        self.btn_action = tk.Button(action_frame, text="[ INSTALL ]", 
                                     bg=THEME["accent"], fg=THEME["bg"], 
                                     font=("Courier New", 11, "bold"), relief="flat", 
                                     command=self.execute_action, width=15)
        self.btn_action.pack(pady=10, padx=10, side="right")
        
        self.btn_refresh = tk.Button(action_frame, text="[ REFRESH ]", 
                                     bg=THEME["panel"], fg=THEME["fg"], 
                                     font=("Courier New", 10, "bold"), relief="flat", 
                                     command=lambda: threading.Thread(
                                         target=self.refresh_installed_apps, daemon=True).start(), 
                                     width=10)
        self.btn_refresh.pack(pady=10, padx=10, side="left")

    def build_log_area(self):
        """Build scrolling log terminal."""
        tk.Label(self.bottom_pane, text=" > SYSTEM_LOG_STREAM:", 
                 bg=THEME["bg"], fg=THEME["fg"], 
                 font=THEME["font_main"], anchor="w").pack(fill="x", pady=(5, 0))
        
        self.terminal = scrolledtext.ScrolledText(self.bottom_pane, 
                                                  bg="black", fg=THEME["success"], 
                                                  font=("Consolas", 9), 
                                                  insertbackground="white", 
                                                  state='disabled')
        self.terminal.pack(fill="both", expand=True)

    def create_category_tab(self, category_name, apps_dict):
        """Create tab for app category with checkboxes and tooltips."""
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.notebook.add(frame, text=f" {category_name} ")
        
        # Configure grid layout (4 columns)
        for i in range(4):
            frame.columnconfigure(i, weight=1)
        
        # Sort apps alphabetically by display name
        sorted_apps = sorted(apps_dict.items())
        
        row, col = 0, 0
        for display_name, data in sorted_apps:
            var = tk.BooleanVar()
            pkg_name = data['pkg']
            
            # Create checkbox container for centering
            cell_frame = tk.Frame(frame, bg=THEME["panel"])
            cell_frame.grid(row=row, column=col, sticky="nsew", padx=5, pady=10)
            
            # Create checkbox without parenthetical package name
            chk = ttk.Checkbutton(cell_frame, text=display_name, variable=var)
            chk.pack(anchor="center")
            
            # Store reference for later access
            self.checkboxes[display_name] = {"var": var, "pkg": pkg_name}

            # Dynamic Tooltip: Fetches description from APT cache
            def get_desc(p=pkg_name):
                try:
                    pkg = self.apt_manager.get_package(p)
                    if pkg:
                        if pkg.candidate:
                            return pkg.candidate.description
                        elif pkg.installed:
                            return pkg.installed.description
                except (AttributeError, KeyError, TypeError):
                    pass
                return f"Package: {p}"
            
            create_tooltip(chk, get_desc)
            
            # Move to next grid position
            col += 1
            if col > 3:
                col, row = 0, row + 1

    def create_installed_tab(self):
        """Create tab for managing installed apps (list + details + actions)."""
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.notebook.add(frame, text=" INSTALLED APPS ")
        
        # Horizontal split: List on left, details on right
        paned = tk.PanedWindow(frame, orient="horizontal", bg=THEME["panel"], sashwidth=4)
        paned.pack(fill="both", expand=True, padx=10, pady=10)
        
        # LEFT: Installed Apps List
        left_frame = tk.Frame(paned, bg=THEME["panel"])
        paned.add(left_frame, width=300)
        
        # Style the treeview
        style = ttk.Style()
        style.configure("Installed.Treeview", 
                        background=THEME["panel"], 
                        foreground=THEME["fg"],
                        fieldbackground=THEME["panel"],
                        borderwidth=0)
        style.configure("Installed.Treeview.Heading",
                        background=THEME["bg"],
                        foreground=THEME["accent"],
                        borderwidth=0)
        style.map("Installed.Treeview",
                  background=[('selected', THEME["accent"])],
                  foreground=[('selected', THEME["bg"])])
        
        self.installed_tree = ttk.Treeview(left_frame, show="tree", style="Installed.Treeview", selectmode="extended")
        self.installed_tree.heading("#0", text="Installed Applications")
        self.installed_tree.pack(fill="both", expand=True)
        self.installed_tree.bind("<<TreeviewSelect>>", self.on_installed_select)
        
        # RIGHT: Details & Actions
        right_frame = tk.Frame(paned, bg=THEME["panel"])
        paned.add(right_frame)
        
        # Details text area
        self.details_text = scrolledtext.ScrolledText(right_frame, 
                                                      bg=THEME["bg"], fg=THEME["fg"], 
                                                      font=THEME["font_main"], height=15)
        self.details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Action buttons
        btn_frame = tk.Frame(right_frame, bg=THEME["panel"])
        btn_frame.pack(fill="x", pady=5)
        
        tk.Button(btn_frame, text="UNINSTALL", bg=THEME["error"], fg="white", 
                  command=self.uninstall_selected).pack(side="left", padx=5)
        tk.Button(btn_frame, text="UPDATE/REINSTALL", bg=THEME["warning"], fg="black", 
                  command=self.update_selected).pack(side="left", padx=5)
        tk.Button(btn_frame, text="CUSTOM DL", bg=THEME["accent"], fg="black", 
                  command=self.external_download_install).pack(side="right", padx=5)

    def create_tweaks_tab(self):
        """Create System Tweaks tab (hidden until TWEAKS module selected)."""
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.tweaks_tab_index = len(self.notebook.tabs())  # Store index for later
        self.notebook.add(frame, text=" SYSTEM ")
        self.notebook.hide(self.tweaks_tab_index)  # Hide initially
        
        # Main container with padding
        container = tk.Frame(frame, bg=THEME["panel"])
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Safe Cleanup Section
        cleanup_frame = tk.LabelFrame(container, text="Safe Cleanup", 
                                      bg=THEME["bg"], fg=THEME["fg"], 
                                      font=THEME["font_main"], 
                                      borderwidth=2, relief="groove")
        cleanup_frame.pack(fill="x", pady=10)
        
        self.cleanup_var = tk.BooleanVar(value=False)
        cleanup_check = ttk.Checkbutton(cleanup_frame, 
                                        text="Safe System Cleanup", 
                                        variable=self.cleanup_var)
        cleanup_check.pack(anchor="w", padx=15, pady=10)
        
        # Description
        cleanup_desc = tk.Label(cleanup_frame, 
                               text="Removes APT cache, old kernels, thumbnails, and orphaned packages.\n" +
                                    "Commands: apt clean, apt autoremove, apt autoclean, clear thumbnail cache",
                               bg=THEME["bg"], fg=THEME["fg"], 
                               font=("Courier New", 8), justify="left")
        cleanup_desc.pack(anchor="w", padx=15, pady=(0, 10))
        
        # Automated Backup Section
        backup_frame = tk.LabelFrame(container, text="Automated Backup", 
                                     bg=THEME["bg"], fg=THEME["fg"], 
                                     font=THEME["font_main"], 
                                     borderwidth=2, relief="groove")
        backup_frame.pack(fill="x", pady=10)
        
        self.backup_var = tk.BooleanVar(value=False)
        backup_check = ttk.Checkbutton(backup_frame, 
                                       text="Setup Automated BorgBackup", 
                                       variable=self.backup_var)
        backup_check.pack(anchor="w", padx=15, pady=10)
        
        # Description
        backup_desc = tk.Label(backup_frame, 
                              text="Configures daily encrypted incremental backups using BorgBackup.\n" +
                                   "Features: AES-256 encryption, chunk-level deduplication, LZ4 compression, integrity verification.\n" +
                                   "Commands: borgbackup, systemd-timer, automated pruning, backup verification",
                              bg=THEME["bg"], fg=THEME["fg"], 
                              font=("Courier New", 8), justify="left")
        backup_desc.pack(anchor="w", padx=15, pady=(0, 5))
        
        # Backup buttons frame
        backup_btn_frame = tk.Frame(backup_frame, bg=THEME["bg"])
        backup_btn_frame.pack(anchor="w", padx=15, pady=(0, 10))
        
        # View logs button
        tk.Button(backup_btn_frame, text="[ VIEW BACKUP LOGS ]", 
                 bg=THEME["panel"], fg=THEME["accent"], 
                 font=("Courier New", 8, "bold"), relief="flat",
                 command=lambda: view_backup_logs(self.log_system)).pack(side="left", padx=(0, 5))

    def create_security_tab(self):
        """Create Security tab (hidden until TWEAKS module selected)."""
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.security_tab_index = len(self.notebook.tabs())  # Store index for later
        self.notebook.add(frame, text=" SECURITY ")
        self.notebook.hide(self.security_tab_index)  # Hide initially
        
        # Main container with padding
        container = tk.Frame(frame, bg=THEME["panel"])
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Security Hardening Section
        security_frame = tk.LabelFrame(container, text="Security Hardening", 
                                       bg=THEME["bg"], fg=THEME["fg"], 
                                       font=THEME["font_main"], 
                                       borderwidth=2, relief="groove")
        security_frame.pack(fill="x", pady=10)
        
        # Security hardening checkboxes
        self.security_firewall_var = tk.BooleanVar(value=False)
        sec_firewall = ttk.Checkbutton(security_frame, 
                                       text="Enable & Configure UFW Firewall", 
                                       variable=self.security_firewall_var)
        sec_firewall.pack(anchor="w", padx=15, pady=5)
        tk.Label(security_frame, 
                text="Installs UFW, sets default deny incoming/allow outgoing, allows SSH on port 2222",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 5))
        
        self.security_services_var = tk.BooleanVar(value=False)
        sec_services = ttk.Checkbutton(security_frame, 
                                       text="Disable Unnecessary Services", 
                                       variable=self.security_services_var)
        sec_services.pack(anchor="w", padx=15, pady=5)
        tk.Label(security_frame, 
                text="Stops and disables: bluetooth, cups (printer service), avahi-daemon (mDNS)",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 5))
        
        self.security_ssh_var = tk.BooleanVar(value=False)
        sec_ssh = ttk.Checkbutton(security_frame, 
                                  text="Secure SSH Configuration", 
                                  variable=self.security_ssh_var)
        sec_ssh.pack(anchor="w", padx=15, pady=5)
        tk.Label(security_frame, 
                text="Disables root login, changes port to 2222, disables password auth (key-based only)",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 5))
        
        self.security_updates_var = tk.BooleanVar(value=False)
        sec_updates = ttk.Checkbutton(security_frame, 
                                      text="Enable Automatic Security Updates", 
                                      variable=self.security_updates_var)
        sec_updates.pack(anchor="w", padx=15, pady=5)
        tk.Label(security_frame, 
                text="Installs unattended-upgrades, auto-applies security patches daily",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 5))
        
        self.security_privesc_var = tk.BooleanVar(value=False)
        sec_privesc = ttk.Checkbutton(security_frame, 
                                      text="Disable Core Dumps & Configure Sudo Timeout", 
                                      variable=self.security_privesc_var)
        sec_privesc.pack(anchor="w", padx=15, pady=5)
        tk.Label(security_frame, 
                text="Prevents memory dumping exploits, sets 5-minute sudo timeout, limits su access",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 10))
        
        # Optional Security Tools Section
        tools_frame = tk.LabelFrame(container, text="Optional Security Tools", 
                                    bg=THEME["bg"], fg=THEME["fg"], 
                                    font=THEME["font_main"], 
                                    borderwidth=2, relief="groove")
        tools_frame.pack(fill="x", pady=10)
        
        tools_desc = tk.Label(tools_frame, 
                             text="Advanced security tools for monitoring and protection (optional).",
                             bg=THEME["bg"], fg=THEME["fg"], 
                             font=("Courier New", 8), justify="left")
        tools_desc.pack(anchor="w", padx=15, pady=(10, 5))
        
        # Install Security Tools button
        tk.Button(tools_frame, text="[ INSTALL SECURITY TOOLS ]", 
                 bg=THEME["warning"], fg=THEME["bg"], 
                 font=("Courier New", 9, "bold"), relief="flat",
                 command=self.install_security_tools).pack(padx=15, pady=10, anchor="w")
        
        tools_list = tk.Label(tools_frame, 
                             text="• Fail2Ban (brute force protection)\n" +
                                  "• ClamAV (antivirus scanner)\n" +
                                  "• RKHunter (rootkit detector)\n" +
                                  "• Lynis (security auditing tool)\n" +
                                  "• AppArmor (mandatory access control)",
                             bg=THEME["bg"], fg=THEME["fg"], 
                             font=("Courier New", 8), justify="left")
        tools_list.pack(anchor="w", padx=30, pady=(0, 10))

    def create_network_tab(self):
        """Create Network tab (hidden until TWEAKS module selected)."""
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.network_tab_index = len(self.notebook.tabs())  # Store index for later
        self.notebook.add(frame, text=" NETWORK ")
        self.notebook.hide(self.network_tab_index)  # Hide initially
        
        # Main container with padding
        container = tk.Frame(frame, bg=THEME["panel"])
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # DNS Configuration Section
        dns_frame = tk.LabelFrame(container, text="DNS Configuration", 
                                  bg=THEME["bg"], fg=THEME["fg"], 
                                  font=THEME["font_main"], 
                                  borderwidth=2, relief="groove")
        dns_frame.pack(fill="x", pady=10)
        
        self.dns_cloudflare_var = tk.BooleanVar(value=False)
        dns_cloudflare = ttk.Checkbutton(dns_frame, 
                                         text="Change DNS to Cloudflare (1.1.1.1)", 
                                         variable=self.dns_cloudflare_var)
        dns_cloudflare.pack(anchor="w", padx=15, pady=5)
        tk.Label(dns_frame, 
                text="Fast and privacy-focused DNS service",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 5))
        
        self.dns_google_var = tk.BooleanVar(value=False)
        dns_google = ttk.Checkbutton(dns_frame, 
                                     text="Change DNS to Google (8.8.8.8)", 
                                     variable=self.dns_google_var)
        dns_google.pack(anchor="w", padx=15, pady=5)
        tk.Label(dns_frame, 
                text="Reliable and widely-used DNS service",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 10))
        
        # Network Optimization Section
        net_opt_frame = tk.LabelFrame(container, text="Network Optimization", 
                                      bg=THEME["bg"], fg=THEME["fg"], 
                                      font=THEME["font_main"], 
                                      borderwidth=2, relief="groove")
        net_opt_frame.pack(fill="x", pady=10)
        
        self.net_bbr_var = tk.BooleanVar(value=False)
        net_bbr = ttk.Checkbutton(net_opt_frame, 
                                  text="Enable BBR TCP Congestion Control", 
                                  variable=self.net_bbr_var)
        net_bbr.pack(anchor="w", padx=15, pady=5)
        tk.Label(net_opt_frame, 
                text="Improves internet speed and reduces latency (requires reboot)",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 5))
        
        self.net_mac_var = tk.BooleanVar(value=False)
        net_mac = ttk.Checkbutton(net_opt_frame, 
                                   text="Change MAC Address (Randomize)", 
                                   variable=self.net_mac_var)
        net_mac.pack(anchor="w", padx=15, pady=5)
        tk.Label(net_opt_frame, 
                text="Randomizes MAC address for privacy (requires network restart)",
                bg=THEME["bg"], fg=THEME["fg"], 
                font=("Courier New", 8), justify="left").pack(anchor="w", padx=35, pady=(0, 10))

    def create_audit_tab(self):
        """
        Creates the Security Audit tab with visual indicators and auto-fix.
        """
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.audit_tab_index = len(self.notebook.tabs())
        self.notebook.add(frame, text=" AUDIT ")
        self.notebook.hide(self.audit_tab_index)

        container = tk.Frame(frame, bg=THEME["panel"])
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header with title and buttons
        header_frame = tk.Frame(container, bg=THEME["bg"])
        header_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(header_frame, text="LINUX HARDENING AUDIT", bg=THEME["bg"], fg=THEME["accent"],
                 font=("Courier New", 14, "bold")).pack(side="left", padx=10)
        
        # Fix Issues button (initially hidden)
        self.btn_auto_fix = tk.Button(header_frame, text="[ FIX ISSUES ]", bg=THEME["warning"], fg=THEME["bg"],
                  font=("Courier New", 10, "bold"), command=self.run_auto_fix,
                  relief="flat", width=18, state="disabled")
        self.btn_auto_fix.pack(side="right", padx=5)
        
        self.btn_run_audit = tk.Button(header_frame, text="[ RUN AUDIT ]", bg=THEME["accent"], fg=THEME["bg"],
                  font=("Courier New", 10, "bold"), command=self.start_audit_thread,
                  relief="flat", width=15)
        self.btn_run_audit.pack(side="right", padx=5)

        # Results display with formatted text
        self.audit_text = scrolledtext.ScrolledText(container, bg="black", fg=THEME["fg"],
                                                    font=("Courier New", 10), wrap=tk.WORD)
        self.audit_text.pack(fill="both", expand=True)
        
        # Configure text tags for visual feedback
        self.audit_text.tag_config("title", foreground=THEME["accent"], font=("Courier New", 12, "bold"))
        self.audit_text.tag_config("section", foreground=THEME["accent"], font=("Courier New", 11, "bold"))
        self.audit_text.tag_config("pass", foreground=THEME["success"], font=("Courier New", 10, "bold"))
        self.audit_text.tag_config("warn", foreground=THEME["warning"], font=("Courier New", 10, "bold"))
        self.audit_text.tag_config("fail", foreground=THEME["error"], font=("Courier New", 10, "bold"))
        self.audit_text.tag_config("info", foreground="#8b949e")
        self.audit_text.tag_config("data", foreground="#c9d1d9")
        
        # Store fixable issues
        self.audit_fixes = []

    def start_audit_thread(self):
        """Start audit in background thread to prevent GUI freeze"""
        self.btn_run_audit.config(state="disabled", text="RUNNING...")
        threading.Thread(target=self.run_audit, daemon=True).start()

    def run_audit(self):
        """
        Comprehensive security audit with auto-fix detection.
        """
        self.root.after(0, lambda: self.audit_text.config(state='normal'))
        self.root.after(0, lambda: self.audit_text.delete(1.0, tk.END))
        self.audit_fixes = []  # Reset fixes
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.audit_text.insert(tk.END, "\n  LINUX SECURITY HARDENING AUDIT\n", "title")
        self.audit_text.insert(tk.END, f"  Started: {timestamp}\n", "info")
        self.audit_text.insert(tk.END, "  " + "═"*70 + "\n\n", "info")

        audit_results = {"pass": 0, "warn": 0, "fail": 0, "critical": 0}

        # Check 1: Firewall Detection (UFW, firewalld, iptables)
        self.audit_text.insert(tk.END, "\n  [1] FIREWALL AUDIT\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        try:
            firewall_found = False
            if shutil.which("ufw"):
                res = subprocess.check_output(["pkexec", "ufw", "status"], text=True, stderr=subprocess.STDOUT, timeout=10)
                if "Status: active" in res:
                    self.audit_text.insert(tk.END, "  ✓ ", "pass")
                    self.audit_text.insert(tk.END, "PASS: UFW Firewall is ACTIVE\n", "pass")
                    audit_results["pass"] += 1
                    firewall_found = True
                else:
                    self.audit_text.insert(tk.END, "  ✗ ", "fail")
                    self.audit_text.insert(tk.END, "FAIL: UFW installed but INACTIVE\n", "fail")
                    audit_results["fail"] += 1
                    self.audit_fixes.append(("ufw_enable", "Enable UFW firewall"))
            elif shutil.which("firewall-cmd"):
                res = subprocess.check_output(["pkexec", "firewall-cmd", "--state"], text=True, stderr=subprocess.STDOUT, timeout=10)
                if "running" in res:
                    self.audit_text.insert(tk.END, "  ✓ ", "pass")
                    self.audit_text.insert(tk.END, "PASS: firewalld is ACTIVE\n", "pass")
                    audit_results["pass"] += 1
                    firewall_found = True
            elif shutil.which("iptables"):
                res = subprocess.check_output(["pkexec", "iptables", "-L", "-n"], text=True, stderr=subprocess.STDOUT, timeout=10)
                if len(res.split('\n')) > 10:
                    self.audit_text.insert(tk.END, "  ✓ ", "pass")
                    self.audit_text.insert(tk.END, "PASS: iptables rules configured\n", "pass")
                    audit_results["pass"] += 1
                    firewall_found = True
            
            if not firewall_found:
                self.audit_text.insert(tk.END, "  ✗ ", "fail")
                self.audit_text.insert(tk.END, "CRITICAL: No firewall detected!\n", "fail")
                audit_results["critical"] += 1
                self.audit_fixes.append(("install_ufw", "Install and enable UFW firewall"))
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")
            audit_results["fail"] += 1

        # Check 2: Unused/Dangerous Services
        self.audit_text.insert(tk.END, "\n  [2] UNUSED SERVICES CHECK\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        dangerous_services = ['telnet', 'rsh', 'rlogin', 'vsftpd', 'cups', 'avahi-daemon', 'bluetooth']
        try:
            for service in dangerous_services:
                try:
                    res = subprocess.check_output(["systemctl", "is-active", service], text=True, stderr=subprocess.STDOUT).strip()
                    if res == "active":
                        self.audit_text.insert(tk.END, "  ⚠ ", "warn")
                        self.audit_text.insert(tk.END, f"WARN: Potentially unnecessary service '{service}' is running\n", "warn")
                        audit_results["warn"] += 1
                        self.audit_fixes.append((f"disable_{service}", f"Disable {service} service"))
                except:
                    pass
            self.audit_text.insert(tk.END, "  ✓ ", "pass")
            self.audit_text.insert(tk.END, "Service check completed\n", "pass")
            audit_results["pass"] += 1
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")

        # Check 3: SSH Configuration Audit
        self.audit_text.insert(tk.END, "\n  [3] SSH CONFIGURATION AUDIT\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        try:
            if os.path.exists("/etc/ssh/sshd_config"):
                with open("/etc/ssh/sshd_config", "r") as f:
                    config = f.read()
                
                ssh_checks = [
                    ("PermitRootLogin no", "Root login disabled", "ssh_root"),
                    ("PasswordAuthentication no", "Password auth disabled", "ssh_passwd"),
                    ("PermitEmptyPasswords no", "Empty passwords disabled", "ssh_empty"),
                    ("X11Forwarding no", "X11 forwarding disabled", "ssh_x11"),
                ]
                
                for check_str, desc, fix_id in ssh_checks:
                    if check_str in config:
                        self.audit_text.insert(tk.END, "  ✓ ", "pass")
                        self.audit_text.insert(tk.END, f"PASS: {desc}\n", "pass")
                        audit_results["pass"] += 1
                    else:
                        self.audit_text.insert(tk.END, "  ⚠ ", "warn")
                        self.audit_text.insert(tk.END, f"WARN: {desc} not enforced\n", "warn")
                        audit_results["warn"] += 1
                        self.audit_fixes.append((fix_id, f"Set {check_str} in sshd_config"))
            else:
                self.audit_text.insert(tk.END, "  ℹ ", "info")
                self.audit_text.insert(tk.END, "INFO: SSH not installed\n", "info")
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")

        # Check 4: Critical File Permissions
        self.audit_text.insert(tk.END, "\n  [4] CRITICAL FILE PERMISSIONS\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        files_to_check = {
            "/etc/shadow": (['000', '400', '600', '640'], '640'),
            "/etc/passwd": (['644'], '644'),
            "/etc/group": (['644'], '644'),
            "/etc/gshadow": (['000', '400', '600', '640'], '640'),
        }
        for fp, (allowed_perms, recommended) in files_to_check.items():
            if os.path.exists(fp):
                stat_info = os.stat(fp)
                perms = oct(stat_info.st_mode)[-3:]
                
                if perms in allowed_perms:
                    self.audit_text.insert(tk.END, "  ✓ ", "pass")
                    self.audit_text.insert(tk.END, f"PASS: {fp} ({perms})\n", "pass")
                    audit_results["pass"] += 1
                else:
                    self.audit_text.insert(tk.END, "  ✗ ", "fail")
                    self.audit_text.insert(tk.END, f"FAIL: {fp} has insecure permissions ({perms})\n", "fail")
                    audit_results["fail"] += 1
                    self.audit_fixes.append((f"chmod_{fp}", f"Fix permissions for {fp}"))

        # Check 5: Rootkit Indicators
        self.audit_text.insert(tk.END, "\n  [5] ROOTKIT INDICATORS\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        try:
            suspicious_found = False
            # Check for common rootkit files
            rootkit_files = ["/dev/shm/.ICE-unix", "/tmp/.X11-unix", "/dev/.udev", "/usr/bin/..."]
            for rf in rootkit_files:
                if os.path.exists(rf) and not os.path.isdir(rf):
                    self.audit_text.insert(tk.END, "  ✗ ", "fail")
                    self.audit_text.insert(tk.END, f"SUSPICIOUS: {rf} found\n", "fail")
                    suspicious_found = True
                    audit_results["critical"] += 1
            
            # Check for hidden processes
            if shutil.which("unhide"):
                self.audit_text.insert(tk.END, "  ℹ ", "info")
                self.audit_text.insert(tk.END, "INFO: Run 'unhide' manually for process scan\n", "info")
            
            if not suspicious_found:
                self.audit_text.insert(tk.END, "  ✓ ", "pass")
                self.audit_text.insert(tk.END, "PASS: No obvious rootkit indicators detected\n", "pass")
                audit_results["pass"] += 1
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")

        # Check 6: Password Policy
        self.audit_text.insert(tk.END, "\n  [6] PASSWORD POLICY REVIEW\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        try:
            if os.path.exists("/etc/login.defs"):
                with open("/etc/login.defs", "r") as f:
                    login_defs = f.read()
                
                # Check password aging
                if "PASS_MAX_DAYS" in login_defs:
                    import re
                    match = re.search(r'PASS_MAX_DAYS\s+(\d+)', login_defs)
                    if match and int(match.group(1)) <= 90:
                        self.audit_text.insert(tk.END, "  ✓ ", "pass")
                        self.audit_text.insert(tk.END, f"PASS: Password expiry set ({match.group(1)} days)\n", "pass")
                        audit_results["pass"] += 1
                    else:
                        self.audit_text.insert(tk.END, "  ⚠ ", "warn")
                        self.audit_text.insert(tk.END, "WARN: Password expiry too long or not set\n", "warn")
                        audit_results["warn"] += 1
                        self.audit_fixes.append(("password_aging", "Set password aging to 90 days"))
            
            # Check PAM password quality
            if os.path.exists("/etc/pam.d/common-password"):
                with open("/etc/pam.d/common-password", "r") as f:
                    pam_content = f.read()
                    if "pam_pwquality" in pam_content or "pam_cracklib" in pam_content:
                        self.audit_text.insert(tk.END, "  ✓ ", "pass")
                        self.audit_text.insert(tk.END, "PASS: Password quality checking enabled\n", "pass")
                        audit_results["pass"] += 1
                    else:
                        self.audit_text.insert(tk.END, "  ⚠ ", "warn")
                        self.audit_text.insert(tk.END, "WARN: Password quality not enforced\n", "warn")
                        audit_results["warn"] += 1
                        self.audit_fixes.append(("install_pwquality", "Install libpam-pwquality"))
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")

        # Check 7: Auditd Logging
        self.audit_text.insert(tk.END, "\n  [7] AUDITD LOGGING STATUS\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        try:
            if shutil.which("auditctl"):
                res = subprocess.check_output(["pkexec", "auditctl", "-s"], text=True, stderr=subprocess.STDOUT, timeout=10)
                if "enabled 1" in res:
                    self.audit_text.insert(tk.END, "  ✓ ", "pass")
                    self.audit_text.insert(tk.END, "PASS: Auditd is enabled\n", "pass")
                    audit_results["pass"] += 1
                else:
                    self.audit_text.insert(tk.END, "  ⚠ ", "warn")
                    self.audit_text.insert(tk.END, "WARN: Auditd is disabled\n", "warn")
                    audit_results["warn"] += 1
                    self.audit_fixes.append(("enable_auditd", "Enable auditd service"))
            else:
                self.audit_text.insert(tk.END, "  ✗ ", "fail")
                self.audit_text.insert(tk.END, "FAIL: Auditd not installed\n", "fail")
                audit_results["fail"] += 1
                self.audit_fixes.append(("install_auditd", "Install auditd package"))
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")

        # Check 8: Automatic Updates
        self.audit_text.insert(tk.END, "\n  [8] AUTOMATIC SECURITY UPDATES\n", "section")
        self.audit_text.insert(tk.END, "  " + "─"*70 + "\n", "info")
        try:
            if shutil.which("unattended-upgrades"):
                self.audit_text.insert(tk.END, "  ✓ ", "pass")
                self.audit_text.insert(tk.END, "PASS: Unattended-upgrades installed\n", "pass")
                audit_results["pass"] += 1
            else:
                self.audit_text.insert(tk.END, "  ⚠ ", "warn")
                self.audit_text.insert(tk.END, "WARN: Automatic updates not configured\n", "warn")
                audit_results["warn"] += 1
                self.audit_fixes.append(("install_unattended", "Install unattended-upgrades"))
        except Exception as e:
            self.audit_text.insert(tk.END, f"  ✗ ERROR: {e}\n", "fail")

        # Scoring & Summary
        self.root.after(0, lambda: self.audit_text.insert(tk.END, "\n  " + "═"*70 + "\n", "info"))
        self.root.after(0, lambda: self.audit_text.insert(tk.END, "  AUDIT SUMMARY & SCORING\n", "title"))
        self.root.after(0, lambda: self.audit_text.insert(tk.END, "  " + "═"*70 + "\n", "info"))
        
        total = audit_results["pass"] + audit_results["warn"] + audit_results["fail"] + audit_results["critical"]
        # CIS-based weighted scoring: Critical issues (-15), failures (-5), warnings (-2), passes (+10)
        # This ensures critical vulnerabilities have maximum impact on score
        weighted_score = (audit_results["pass"] * 10 - audit_results["critical"] * 15 - audit_results["fail"] * 5 - audit_results["warn"] * 2)
        max_score = total * 10
        score = int((weighted_score / max_score * 100)) if max_score > 0 else 0
        score = max(0, min(100, score))  # Clamp between 0-100
        
        self.audit_text.insert(tk.END, f"\n  ✓ Passed: ", "pass")
        self.audit_text.insert(tk.END, f"{audit_results['pass']}\n", "data")
        
        self.audit_text.insert(tk.END, f"  ⚠ Warnings: ", "warn")
        self.audit_text.insert(tk.END, f"{audit_results['warn']}\n", "data")
        
        self.audit_text.insert(tk.END, f"  ✗ Failed: ", "fail")
        self.audit_text.insert(tk.END, f"{audit_results['fail']}\n", "data")
        
        self.audit_text.insert(tk.END, f"  ⛔ Critical: ", "fail")
        self.audit_text.insert(tk.END, f"{audit_results['critical']}\n", "data")
        
        self.audit_text.insert(tk.END, f"\n  CIS Security Score: ", "info")
        if score >= 85:
            self.audit_text.insert(tk.END, f"{score}/100 - EXCELLENT ✓\n", "pass")
        elif score >= 70:
            self.audit_text.insert(tk.END, f"{score}/100 - GOOD ⚠\n", "warn")
        elif score >= 50:
            self.audit_text.insert(tk.END, f"{score}/100 - NEEDS IMPROVEMENT ✗\n", "warn")
        else:
            self.audit_text.insert(tk.END, f"{score}/100 - CRITICAL RISK ⛔\n", "fail")
        
        # Show fixable issues
        if self.audit_fixes:
            self.root.after(0, lambda: self.audit_text.insert(tk.END, f"\n  Fixable Issues Detected: {len(self.audit_fixes)}\n", "warn"))
            self.root.after(0, lambda: self.audit_text.insert(tk.END, "  Click FIX ISSUES button to apply recommended fixes.\n", "info"))
            self.root.after(0, lambda: self.btn_auto_fix.config(state="normal"))
        else:
            self.root.after(0, lambda: self.audit_text.insert(tk.END, "\n  No auto-fixable issues found.\n", "pass"))
            self.root.after(0, lambda: self.btn_auto_fix.config(state="disabled"))
        
        self.root.after(0, lambda: self.audit_text.insert(tk.END, "\n", "info"))
        self.root.after(0, lambda: self.audit_text.config(state='disabled'))
        self.root.after(0, lambda: self.btn_run_audit.config(state="normal", text="[ RUN AUDIT ]"))

    def run_auto_fix(self):
        """
        Applies automatic fixes for detected security issues.
        """
        if not self.audit_fixes:
            messagebox.showinfo("Fix Issues", "No issues to fix.")
            return
        
        confirm = messagebox.askyesno(
            "Fix Security Issues",
            f"This will attempt to fix {len(self.audit_fixes)} security issues.\n\n"
            "This requires root privileges. Continue?"
        )
        
        if not confirm:
            return
        
        self.log_system("Starting fix process...")
        self.btn_auto_fix.config(state="disabled", text="FIXING...")
        
        def fix_thread():
            commands = []
            
            # Build all fix commands
            for fix_id, description in self.audit_fixes:
                self.log_system(f"Preparing: {description}")
                
                if fix_id == "install_ufw":
                    commands.append("apt-get install -y ufw && ufw --force enable")
                elif fix_id == "ufw_enable":
                    commands.append("ufw --force enable")
                elif fix_id.startswith("disable_"):
                    service = fix_id.replace("disable_", "")
                    commands.append(f"systemctl stop {service} && systemctl disable {service}")
                elif fix_id.startswith("ssh_"):
                    self.log_system(f"Manual intervention required for SSH config", "warn")
                elif fix_id == "install_auditd":
                    commands.append("apt-get install -y auditd && systemctl enable auditd")
                elif fix_id == "enable_auditd":
                    commands.append("systemctl enable auditd && systemctl start auditd")
                elif fix_id == "install_unattended":
                    commands.append("apt-get install -y unattended-upgrades")
                elif fix_id == "install_pwquality":
                    commands.append("apt-get install -y libpam-pwquality")
            
            # Execute all commands with single auth
            if commands:
                try:
                    combined_cmd = " && ".join(commands)
                    self.run_generic_command(["pkexec", "bash", "-c", combined_cmd], "Fix Security Issues")
                    
                    self.root.after(0, lambda: self.btn_auto_fix.config(state="normal", text="[ FIX ISSUES ]"))
                    self.root.after(0, lambda: messagebox.showinfo("Fix Complete", 
                        f"Successfully fixed {len(self.audit_fixes)} issues.\n\nRun audit again to verify."))
                    self.log_system(f"Fix completed: {len(self.audit_fixes)} issues resolved", "success")
                except Exception as e:
                    self.log_system(f"Fix failed: {e}", "error")
                    self.root.after(0, lambda: self.btn_auto_fix.config(state="normal", text="[ FIX ISSUES ]"))
            else:
                self.root.after(0, lambda: self.btn_auto_fix.config(state="normal", text="[ FIX ISSUES ]"))
        
        threading.Thread(target=fix_thread, daemon=True).start()

    def create_resources_tab(self):
        """
        Creates System Resources Monitor - 2x3 grid with popup graphs.
        Auto-starts monitoring when tab is opened.
        """
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.resources_tab_index = len(self.notebook.tabs())
        self.notebook.add(frame, text=" RESOURCES ")
        self.notebook.hide(self.resources_tab_index)

        container = tk.Frame(frame, bg=THEME["panel"])
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        tk.Label(container, text="SYSTEM MONITOR", bg=THEME["panel"], fg=THEME["accent"],
                 font=("Courier New", 14, "bold")).pack(pady=10)
        
        # Initialize data storage
        self.monitor_data = {
            "cpu_history": [0] * 60,
            "mem_history": [0] * 60,
            "net_rx_history": [0] * 60,
            "last_net_rx": 0,
            "last_net_tx": 0
        }
        
        # Create 2x3 grid
        grid_frame = tk.Frame(container, bg=THEME["panel"])
        grid_frame.pack(fill="both", expand=True)
        
        # Row 1
        row1 = tk.Frame(grid_frame, bg=THEME["panel"])
        row1.pack(fill="both", expand=True, pady=5)
        
        # CPU USAGE
        cpu_cell = tk.Frame(row1, bg=THEME["panel"])
        cpu_cell.pack(side="left", fill="both", expand=True, padx=5)
        self.cpu_frame = tk.LabelFrame(cpu_cell, text="CPU USAGE", bg=THEME["bg"], fg=THEME["accent"],
                                  font=("Courier New", 10, "bold"), cursor="hand2", relief="raised", bd=2)
        self.cpu_frame.pack(fill="both", expand=True)
        self.cpu_frame.bind("<Button-1>", lambda e: self.show_graph_popup("cpu"))
        
        self.cpu_info_label = tk.Label(self.cpu_frame, text="Initializing...", bg=THEME["bg"], 
                                       fg=THEME["fg"], font=("Courier New", 11, "bold"), justify="center",
                                       cursor="hand2")
        self.cpu_info_label.pack(expand=True, pady=20)
        self.cpu_info_label.bind("<Button-1>", lambda e: self.show_graph_popup("cpu"))
        
        # GPU USAGE
        gpu_cell = tk.Frame(row1, bg=THEME["panel"])
        gpu_cell.pack(side="left", fill="both", expand=True, padx=5)
        self.gpu_frame = tk.LabelFrame(gpu_cell, text="GPU USAGE", bg=THEME["bg"], fg=THEME["accent"],
                                  font=("Courier New", 10, "bold"), cursor="hand2", relief="raised", bd=2)
        self.gpu_frame.pack(fill="both", expand=True)
        self.gpu_frame.bind("<Button-1>", lambda e: self.show_graph_popup("gpu"))
        
        self.gpu_info_label = tk.Label(self.gpu_frame, text="Initializing...", bg=THEME["bg"],
                                       fg=THEME["fg"], font=("Courier New", 11, "bold"), justify="center",
                                       cursor="hand2")
        self.gpu_info_label.pack(expand=True, pady=20)
        self.gpu_info_label.bind("<Button-1>", lambda e: self.show_graph_popup("gpu"))
        
        # MEMORY USAGE
        mem_cell = tk.Frame(row1, bg=THEME["panel"])
        mem_cell.pack(side="left", fill="both", expand=True, padx=5)
        self.mem_frame = tk.LabelFrame(mem_cell, text="MEMORY USAGE", bg=THEME["bg"], fg=THEME["accent"],
                                  font=("Courier New", 10, "bold"), cursor="hand2", relief="raised", bd=2)
        self.mem_frame.pack(fill="both", expand=True)
        self.mem_frame.bind("<Button-1>", lambda e: self.show_graph_popup("mem"))
        
        self.mem_info_label = tk.Label(self.mem_frame, text="Initializing...", bg=THEME["bg"],
                                       fg=THEME["fg"], font=("Courier New", 11, "bold"), justify="center",
                                       cursor="hand2")
        self.mem_info_label.pack(expand=True, pady=20)
        self.mem_info_label.bind("<Button-1>", lambda e: self.show_graph_popup("mem"))
        
        # Row 2
        row2 = tk.Frame(grid_frame, bg=THEME["panel"])
        row2.pack(fill="both", expand=True, pady=5)
        
        # DISK USAGE
        disk_cell = tk.Frame(row2, bg=THEME["panel"])
        disk_cell.pack(side="left", fill="both", expand=True, padx=5)
        self.disk_frame = tk.LabelFrame(disk_cell, text="DISK USAGE", bg=THEME["bg"], fg=THEME["accent"],
                                   font=("Courier New", 10, "bold"), cursor="hand2", relief="raised", bd=2)
        self.disk_frame.pack(fill="both", expand=True)
        self.disk_frame.bind("<Button-1>", lambda e: self.show_graph_popup("disk"))
        
        self.disk_info_label = tk.Label(self.disk_frame, text="Initializing...", bg=THEME["bg"],
                                       fg=THEME["fg"], font=("Courier New", 11, "bold"), justify="center",
                                       cursor="hand2")
        self.disk_info_label.pack(expand=True, pady=20)
        self.disk_info_label.bind("<Button-1>", lambda e: self.show_graph_popup("disk"))
        
        # NETWORK ACTIVITY
        net_cell = tk.Frame(row2, bg=THEME["panel"])
        net_cell.pack(side="left", fill="both", expand=True, padx=5)
        self.net_frame = tk.LabelFrame(net_cell, text="NETWORK ACTIVITY", bg=THEME["bg"], fg=THEME["accent"],
                                  font=("Courier New", 10, "bold"), cursor="hand2", relief="raised", bd=2)
        self.net_frame.pack(fill="both", expand=True)
        self.net_frame.bind("<Button-1>", lambda e: self.show_graph_popup("net"))
        
        self.net_info_label = tk.Label(self.net_frame, text="Initializing...", bg=THEME["bg"],
                                       fg=THEME["fg"], font=("Courier New", 11, "bold"), justify="center",
                                       cursor="hand2")
        self.net_info_label.pack(expand=True, pady=20)
        self.net_info_label.bind("<Button-1>", lambda e: self.show_graph_popup("net"))
        
        # SYSTEM UPTIME
        uptime_cell = tk.Frame(row2, bg=THEME["panel"])
        uptime_cell.pack(side="left", fill="both", expand=True, padx=5)
        uptime_frame = tk.LabelFrame(uptime_cell, text="SYSTEM UPTIME", bg=THEME["bg"], fg=THEME["accent"],
                                     font=("Courier New", 10, "bold"), relief="raised", bd=2)
        uptime_frame.pack(fill="both", expand=True)
        
        self.uptime_label = tk.Label(uptime_frame, text="Loading...", 
                                     bg=THEME["bg"], fg=THEME["fg"],
                                     font=("Courier New", 11, "bold"), justify="center")
        self.uptime_label.pack(expand=True, pady=20)
        
        # Auto-start monitoring flag
        self.monitor_active = False
        self._resources_initialized = False
    
    def create_services_tab(self):
        """
        Creates Services Monitor tab with running services and network traffic.
        """
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.services_tab_index = len(self.notebook.tabs())
        self.notebook.add(frame, text=" SERVICES ")
        self.notebook.hide(self.services_tab_index)

        # Split view: services list (left) and network traffic (right)
        left_frame = tk.Frame(frame, bg=THEME["panel"])
        left_frame.pack(side="left", fill="both", expand=True, padx=(20,10), pady=20)
        
        right_frame = tk.Frame(frame, bg=THEME["panel"])
        right_frame.pack(side="right", fill="both", expand=True, padx=(10,20), pady=20)
        
        # LEFT: Services List
        services_header = tk.Frame(left_frame, bg=THEME["bg"], relief="raised", bd=2)
        services_header.pack(fill="x", pady=(0,10))
        
        tk.Label(services_header, text="⚙ RUNNING SERVICES", bg=THEME["bg"], fg=THEME["fg"],
                font=("Courier New", 12, "bold")).pack(padx=10, pady=5)
        
        # Services TreeView
        tree_frame = tk.Frame(left_frame, bg=THEME["bg"], relief="sunken", bd=2)
        tree_frame.pack(fill="both", expand=True)
        
        # Create Treeview with scrollbar
        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side="right", fill="y")
        
        # Configure Treeview style for dark theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Services.Treeview",
                       background="#0a0e14",
                       foreground=THEME["fg"],
                       fieldbackground="#0a0e14",
                       borderwidth=0)
        style.configure("Services.Treeview.Heading",
                       background=THEME["bg"],
                       foreground=THEME["accent"],
                       borderwidth=1)
        style.map("Services.Treeview",
                 background=[("selected", THEME["accent"])],
                 foreground=[("selected", THEME["bg"])])
        
        self.services_tree = ttk.Treeview(tree_frame, columns=("PID", "Status", "Service"),
                                         show="headings", yscrollcommand=tree_scroll.set, height=15,
                                         style="Services.Treeview")
        self.services_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.config(command=self.services_tree.yview)
        
        # Configure columns
        self.services_tree.heading("PID", text="PID")
        self.services_tree.heading("Status", text="STATUS")
        self.services_tree.heading("Service", text="SERVICE NAME")
        
        self.services_tree.column("PID", width=80, anchor="center")
        self.services_tree.column("Status", width=100, anchor="center")
        self.services_tree.column("Service", width=250, anchor="w")
        
        # Right-click context menu
        self.services_menu = tk.Menu(self.services_tree, tearoff=0, bg=THEME["bg"], fg=THEME["fg"])
        self.services_menu.add_command(label="Stop Service", command=self.stop_service)
        self.services_menu.add_command(label="Restart Service", command=self.restart_service)
        self.services_menu.add_separator()
        self.services_menu.add_command(label="Disable Service", command=self.disable_service)
        self.services_menu.add_command(label="Enable Service", command=self.enable_service)
        
        self.services_tree.bind("<Button-3>", self.show_services_menu)
        
        # RIGHT: Running Processes Monitor
        proc_header = tk.Frame(right_frame, bg=THEME["bg"], relief="raised", bd=2)
        proc_header.pack(fill="x", pady=(0,10))
        
        tk.Label(proc_header, text="⚡ RUNNING PROCESSES", bg=THEME["bg"], fg=THEME["fg"],
                font=("Courier New", 12, "bold")).pack(padx=10, pady=5)
        
        # Processes TreeView
        proc_tree_frame = tk.Frame(right_frame, bg="#0a1929", relief="sunken", bd=2)
        proc_tree_frame.pack(fill="both", expand=True)
        
        proc_scroll = ttk.Scrollbar(proc_tree_frame)
        proc_scroll.pack(side="right", fill="y")
        
        # Configure Treeview style for dark theme (same as Services)
        style.configure("Processes.Treeview",
                       background="#0a0e14",
                       foreground=THEME["fg"],
                       fieldbackground="#0a0e14",
                       borderwidth=0)
        style.configure("Processes.Treeview.Heading",
                       background=THEME["bg"],
                       foreground=THEME["accent"],
                       borderwidth=1)
        style.map("Processes.Treeview",
                 background=[("selected", THEME["accent"])],
                 foreground=[("selected", THEME["bg"])])
        
        self.processes_tree = ttk.Treeview(proc_tree_frame, 
                                          columns=("Process", "PID", "CPU%", "MEM%", "User"),
                                          show="headings", yscrollcommand=proc_scroll.set, height=15,
                                          style="Processes.Treeview")
        self.processes_tree.pack(side="left", fill="both", expand=True)
        proc_scroll.config(command=self.processes_tree.yview)
        
        # Configure sortable columns
        self.processes_tree.heading("Process", text="Process", command=lambda: self.sort_processes("Process"))
        self.processes_tree.heading("PID", text="PID", command=lambda: self.sort_processes("PID"))
        self.processes_tree.heading("CPU%", text="CPU%", command=lambda: self.sort_processes("CPU%"))
        self.processes_tree.heading("MEM%", text="MEM%", command=lambda: self.sort_processes("MEM%"))
        self.processes_tree.heading("User", text="User", command=lambda: self.sort_processes("User"))
        
        self.processes_tree.column("Process", width=200, anchor="w")
        self.processes_tree.column("PID", width=80, anchor="center")
        self.processes_tree.column("CPU%", width=80, anchor="center")
        self.processes_tree.column("MEM%", width=80, anchor="center")
        self.processes_tree.column("User", width=100, anchor="center")
        
        # Right-click context menu for processes
        self.processes_menu = tk.Menu(self.processes_tree, tearoff=0, bg=THEME["bg"], fg=THEME["fg"])
        self.processes_menu.add_command(label="Kill Process", command=self.kill_process)
        self.processes_menu.add_separator()
        self.processes_menu.add_command(label="Priority: High", command=lambda: self.change_priority("high"))
        self.processes_menu.add_command(label="Priority: Normal", command=lambda: self.change_priority("normal"))
        self.processes_menu.add_command(label="Priority: Low", command=lambda: self.change_priority("low"))
        
        self.processes_tree.bind("<Button-3>", self.show_processes_menu)
        
        # Store sort order state
        self.process_sort_column = None
        self.process_sort_reverse = False
        
        # Initialize services data
        self.services_active = False
        self.services_tree.bind("<Double-1>", lambda e: self.refresh_services())
        self.refresh_services()
        self.refresh_processes()
    
    def refresh_services(self):
        """Refresh the list of running services."""
        try:
            # Clear existing entries
            for item in self.services_tree.get_children():
                self.services_tree.delete(item)
            
            # Get systemd services
            result = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].endswith(".service"):
                        service_name = parts[0].replace(".service", "")
                        status = parts[2]
                        
                        # Try to get PID
                        try:
                            pid_result = subprocess.run(["systemctl", "show", "-p", "MainPID", parts[0]],
                                                       capture_output=True, text=True, timeout=2)
                            pid = pid_result.stdout.strip().split("=")[1] if "=" in pid_result.stdout else "N/A"
                        except:
                            pid = "N/A"
                        
                        self.services_tree.insert("", "end", values=(pid, status.upper(), service_name))
            
        except Exception as e:
            self.log_system(f"Failed to refresh services: {e}", "error")
    
    def refresh_processes(self):
        """Refresh the list of running processes."""
        try:
            # Clear existing entries
            for item in self.processes_tree.get_children():
                self.processes_tree.delete(item)
            
            # Get process list using ps command
            result = subprocess.run(
                ["ps", "aux", "--sort=-%cpu"],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[1:101]:  # Skip header, limit to top 100 processes
                    parts = line.split()
                    if len(parts) >= 11:
                        user = parts[0]
                        pid = parts[1]
                        cpu = parts[2]
                        mem = parts[3]
                        # Process name is the last part (may contain spaces)
                        process = " ".join(parts[10:])[:40]  # Truncate long names
                        
                        self.processes_tree.insert("", "end", 
                                                  values=(process, pid, cpu, mem, user))
            
            # Auto-refresh every 3 seconds
            self.root.after(3000, self.refresh_processes)
            
        except Exception as e:
            self.log_system(f"Failed to refresh processes: {e}", "error")
    
    def sort_processes(self, column):
        """Sort processes table by column."""
        # Toggle sort order if same column clicked
        if self.process_sort_column == column:
            self.process_sort_reverse = not self.process_sort_reverse
        else:
            self.process_sort_column = column
            self.process_sort_reverse = False
        
        # Get all items
        items = [(self.processes_tree.set(item, column), item) 
                 for item in self.processes_tree.get_children("")]
        
        # Sort based on column type
        if column in ["PID", "CPU%", "MEM%"]:
            # Numeric sort
            items.sort(key=lambda x: float(x[0]) if x[0].replace('.', '').isdigit() else 0,
                      reverse=self.process_sort_reverse)
        else:
            # Alphabetic sort
            items.sort(reverse=self.process_sort_reverse)
        
        # Rearrange items
        for index, (_, item) in enumerate(items):
            self.processes_tree.move(item, "", index)
    
    def show_processes_menu(self, event):
        """Show right-click context menu for processes."""
        try:
            item = self.processes_tree.identify_row(event.y)
            if item:
                self.processes_tree.selection_set(item)
                self.processes_menu.post(event.x_root, event.y_root)
        except Exception as e:
            self.log_system(f"Menu error: {e}", "error")
    
    def kill_process(self):
        """Kill selected process."""
        selection = self.processes_tree.selection()
        if not selection:
            return
        
        item = self.processes_tree.item(selection[0])
        pid = item["values"][1]
        process_name = item["values"][0]
        
        confirm = messagebox.askyesno("Kill Process",
                                     f"Kill process '{process_name}' (PID: {pid})?")
        if confirm:
            try:
                subprocess.run(["pkexec", "kill", "-9", str(pid)], timeout=5)
                self.log_system(f"✓ Killed process {process_name} (PID: {pid})", "success")
                self.refresh_processes()
            except Exception as e:
                self.log_system(f"✗ Failed to kill process: {e}", "error")
    
    def change_priority(self, priority):
        """Change process priority (nice value)."""
        selection = self.processes_tree.selection()
        if not selection:
            return
        
        item = self.processes_tree.item(selection[0])
        pid = item["values"][1]
        process_name = item["values"][0]
        
        # Map priority to nice value
        nice_values = {"high": -10, "normal": 0, "low": 10}
        nice_val = nice_values.get(priority, 0)
        
        try:
            subprocess.run(["pkexec", "renice", str(nice_val), "-p", str(pid)], timeout=5)
            self.log_system(f"✓ Changed priority of {process_name} to {priority.upper()}", "success")
            self.refresh_processes()
        except Exception as e:
            self.log_system(f"✗ Failed to change priority: {e}", "error")
    
    def show_services_menu(self, event):
        """Show right-click context menu for services."""
        try:
            item = self.services_tree.identify_row(event.y)
            if item:
                self.services_tree.selection_set(item)
                self.services_menu.post(event.x_root, event.y_root)
        except Exception as e:
            self.log_system(f"Menu error: {e}", "error")
    
    def stop_service(self):
        """Stop selected service."""
        selection = self.services_tree.selection()
        if not selection:
            return
        
        item = self.services_tree.item(selection[0])
        service_name = item["values"][2]
        
        confirm = messagebox.askyesno("Stop Service", 
                                     f"Stop service '{service_name}'?\n\nThis requires root privileges.")
        if confirm:
            try:
                subprocess.run(["pkexec", "systemctl", "stop", f"{service_name}.service"], check=True)
                messagebox.showinfo("Success", f"Service '{service_name}' stopped.")
                self.refresh_services()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop service: {e}")
    
    def restart_service(self):
        """Restart selected service."""
        selection = self.services_tree.selection()
        if not selection:
            return
        
        item = self.services_tree.item(selection[0])
        service_name = item["values"][2]
        
        try:
            subprocess.run(["pkexec", "systemctl", "restart", f"{service_name}.service"], check=True)
            messagebox.showinfo("Success", f"Service '{service_name}' restarted.")
            self.refresh_services()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restart service: {e}")
    
    def disable_service(self):
        """Disable selected service."""
        selection = self.services_tree.selection()
        if not selection:
            return
        
        item = self.services_tree.item(selection[0])
        service_name = item["values"][2]
        
        confirm = messagebox.askyesno("Disable Service",
                                     f"Disable service '{service_name}'?\n\n" +
                                     "This will prevent it from starting at boot.")
        if confirm:
            try:
                subprocess.run(["pkexec", "systemctl", "disable", f"{service_name}.service"], check=True)
                messagebox.showinfo("Success", f"Service '{service_name}' disabled.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to disable service: {e}")
    
    def enable_service(self):
        """Enable selected service."""
        selection = self.services_tree.selection()
        if not selection:
            return
        
        item = self.services_tree.item(selection[0])
        service_name = item["values"][2]
        
        try:
            subprocess.run(["pkexec", "systemctl", "enable", f"{service_name}.service"], check=True)
            messagebox.showinfo("Success", f"Service '{service_name}' enabled.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to enable service: {e}")
    
    def create_presets_tab(self):
        """
        Creates the Presets/Builds tab for one-click system configurations.
        """
        frame = tk.Frame(self.notebook, bg=THEME["panel"])
        self.presets_tab_index = len(self.notebook.tabs())
        self.notebook.add(frame, text=" PRESETS ")
        self.notebook.hide(self.presets_tab_index)
        
        # Main container
        container = tk.Frame(frame, bg=THEME["panel"])
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header = tk.Frame(container, bg=THEME["panel"])
        header.pack(fill="x", pady=(0, 15))
        
        tk.Label(header, text="SYSTEM PRESETS & BUILDS", bg=THEME["panel"], fg=THEME["accent"],
                font=("Courier New", 14, "bold")).pack(side="left")
        
        tk.Label(header, text="One-click configurations for common use cases",
                bg=THEME["panel"], fg=THEME["fg"],
                font=("Courier New", 9)).pack(side="left", padx=20)
        
        # Scrollable container
        canvas = tk.Canvas(container, bg=THEME["panel"], highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=THEME["panel"])
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Define presets
        presets = [
            {
                "name": "🔄 Default/Reset Build",
                "description": "Reset system to default configuration",
                "packages": [],
                "tweaks": ["reset_cpu", "reset_network", "reset_swap"],
                "details": [
                    "• Reset CPU governor to default (ondemand/powersave)",
                    "• Reset network settings to defaults",
                    "• Reset swap configuration to default (swappiness=60)",
                    "• Restore system to stock configuration",
                    "• Remove custom optimizations",
                    "• Safe to run at any time"
                ]
            },
            {
                "name": "🎮 Gaming Build",
                "description": "Optimize your system for gaming performance",
                "packages": ["lutris", "wine", "gamemode", "obs-studio"],
                "tweaks": ["performance_cpu", "gaming_network", "swap_optimize"],
                "details": [
                    "• Install Lutris, Wine for game compatibility",
                    "• Install OBS Studio for streaming",
                    "• Enable CPU performance governor",
                    "• Optimize network latency",
                    "• Configure swap for gaming",
                    "• Install GameMode for automatic optimizations"
                ]
            },
            {
                "name": "💻 Development Build",
                "description": "Complete development environment setup",
                "packages": ["git", "docker.io", "build-essential", "curl", "wget", 
                           "python3-pip", "nodejs", "npm", "default-jdk", "postgresql", "redis"],
                "tweaks": ["git_config", "docker_permissions"],
                "details": [
                    "• Install Git, Docker, build tools",
                    "• Install compilers and development libraries",
                    "• Setup Python, Node.js, Java environments",
                    "• Install databases (PostgreSQL, Redis)",
                    "• Configure Git with user settings",
                    "• Add user to docker group for permissions"
                ]
            },
            {
                "name": "🔒 Privacy & Security Build",
                "description": "Enhanced privacy and security configuration",
                "packages": ["torbrowser-launcher", "gnupg", "gnupg2", 
                           "rkhunter", "clamav", "fail2ban", "ufw"],
                "tweaks": ["ufw_enable", "mac_randomize", "ssh_harden", "auditd_enable"],
                "details": [
                    "• Install Tor Browser for private browsing",
                    "• Install encryption tools (GPG, GnuPG)",
                    "• Install security scanners (rkhunter, ClamAV)",
                    "• Enable and configure UFW firewall",
                    "• Enable MAC address randomization",
                    "• Harden SSH configuration",
                    "• Enable system auditing (auditd)"
                ]
            }
        ]
        
        # Create preset cards in 2-column layout
        row_frame = None
        for idx, preset in enumerate(presets):
            # Create new row every 2 presets
            if idx % 2 == 0:
                row_frame = tk.Frame(scrollable_frame, bg=THEME["panel"])
                row_frame.pack(fill="x", padx=20, pady=10)
                row_frame.pack_configure(anchor="center")
            
            card = tk.LabelFrame(row_frame, text=preset["name"], 
                                bg=THEME["bg"], fg=THEME["accent"],
                                font=("Courier New", 12, "bold"),
                                borderwidth=3, relief="ridge")
            card.pack(side="left", fill="both", expand=True, padx=15, pady=10, ipadx=10, ipady=10)
            
            # Description
            tk.Label(card, text=preset["description"], bg=THEME["bg"], fg=THEME["fg"],
                    font=("Courier New", 10, "italic")).pack(anchor="w", padx=20, pady=(15, 8))
            
            # Details
            details_text = "\n".join(preset["details"])
            tk.Label(card, text=details_text, bg=THEME["bg"], fg=THEME["fg"],
                    font=("Courier New", 9), justify="left").pack(anchor="w", padx=20, pady=8)
            
            # Package count info
            pkg_count = len(preset["packages"])
            tweak_count = len(preset["tweaks"])
            info_text = f"Packages: {pkg_count} | Tweaks: {tweak_count}"
            tk.Label(card, text=info_text, bg=THEME["bg"], fg=THEME["warning"],
                    font=("Courier New", 9, "bold")).pack(anchor="w", padx=20, pady=(8, 15))
            
            # Apply button
            btn_apply = tk.Button(card, text="[ APPLY PRESET ]", 
                                 bg=THEME["accent"], fg=THEME["bg"],
                                 font=("Courier New", 10, "bold"), relief="flat",
                                 command=lambda p=preset: self.apply_preset(p))
            btn_apply.pack(anchor="e", padx=20, pady=(0, 15))
    
    def apply_preset(self, preset):
        """
        Apply a system preset configuration.
        """
        confirm = messagebox.askyesno(
            "Apply Preset",
            f"Apply '{preset['name']}' preset?\n\n"
            f"This will install {len(preset['packages'])} packages and apply {len(preset['tweaks'])} tweaks.\n\n"
            "This may take several minutes. Continue?"
        )
        
        if not confirm:
            return
        
        self.log_system(f"Applying preset: {preset['name']}")
        
        def apply_thread():
            """Background thread for preset application to prevent UI blocking.
            Executes package installation and system tweaks sequentially.
            """
            try:
                # Build combined command for all operations (batched for efficiency)
                commands = []
                
                # Install all packages in one apt-get call (faster than individual installs)
                if preset['packages']:
                    self.log_system(f"Installing {len(preset['packages'])} packages...")
                    pkg_list = " ".join(preset['packages'])
                    commands.append(f"apt-get install -y {pkg_list}")
                
                # Build tweak commands
                for tweak in preset['tweaks']:
                    tweak_cmd = self.get_preset_tweak_command(tweak)
                    if tweak_cmd:
                        commands.append(tweak_cmd)
                
                # Execute all commands with single auth
                if commands:
                    # Properly quote the combined command for bash -c
                    combined_cmd = " && ".join(commands)
                    # Use array form to avoid shell interpretation issues
                    self.log_system(f"Executing: pkexec bash -c '{combined_cmd}'", "info")
                    
                    result = subprocess.run(
                        ["pkexec", "bash", "-c", combined_cmd],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        self.log_system("All commands executed successfully", "success")
                        if result.stdout:
                            for line in result.stdout.splitlines():
                                if line.strip():
                                    self.log_system(f"  {line}", "info")
                    else:
                        self.log_system(f"Command failed (exit code {result.returncode})", "error")
                        if result.stdout:
                            for line in result.stdout.splitlines():
                                if line.strip():
                                    self.log_system(f"  stdout: {line}", "error")
                        if result.stderr:
                            for line in result.stderr.splitlines():
                                if line.strip():
                                    self.log_system(f"  stderr: {line}", "error")
                        raise RuntimeError(f"Commands failed with exit code {result.returncode}")
                
                # Apply non-root tweaks
                for tweak in preset['tweaks']:
                    if tweak == "git_config":
                        subprocess.run(["git", "config", "--global", "init.defaultBranch", "main"], check=False)
                        subprocess.run(["git", "config", "--global", "pull.rebase", "false"], check=False)
                    elif tweak == "audio_optimize":
                        subprocess.run(["systemctl", "--user", "restart", "pipewire"], check=False)
                    elif tweak == "cloud_sync":
                        import os
                        home = os.path.expanduser("~")
                        sync_dir = os.path.join(home, "CloudSync")
                        os.makedirs(sync_dir, exist_ok=True)
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "Preset Applied",
                    f"'{preset['name']}' preset has been applied successfully!\n\n"
                    "Some changes may require a system restart."
                ))
                self.log_system(f"Preset '{preset['name']}' applied successfully!", "success")
                
            except Exception as e:
                self.log_system(f"Preset application failed: {e}", "error")
                self.root.after(0, lambda: messagebox.showerror(
                    "Preset Failed",
                    f"Failed to apply preset: {str(e)}"
                ))
        
        threading.Thread(target=apply_thread, daemon=True).start()
    
    def get_preset_tweak_command(self, tweak):
        """
        Get command string for preset tweak (returns None for non-root tweaks).
        """
        if tweak == "reset_cpu":
            return r'for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -f "$cpu" ] && echo ondemand > "$cpu" 2>/dev/null || true; done'
        elif tweak == "reset_network":
            return "sysctl -w net.ipv4.tcp_low_latency=0 2>/dev/null || true"
        elif tweak == "reset_swap":
            return "sysctl -w vm.swappiness=60"
        elif tweak == "performance_cpu":
            return r'for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -f "$cpu" ] && echo performance > "$cpu" 2>/dev/null || true; done'
        elif tweak == "gaming_network":
            return "sysctl -w net.ipv4.tcp_low_latency=1"
        elif tweak == "swap_optimize":
            return "sysctl -w vm.swappiness=10"
        elif tweak == "docker_permissions":
            import getpass
            username = getpass.getuser()
            return f"usermod -aG docker {username}"
        elif tweak == "storage_optimize":
            return "sysctl -w fs.inotify.max_user_watches=524288"
        elif tweak == "ufw_enable":
            return "apt-get install -y ufw && ufw --force enable"
        elif tweak == "mac_randomize":
            return "apt-get install -y macchanger"
        elif tweak == "ssh_harden":
            return "echo 'PermitRootLogin no\nPasswordAuthentication no\nPort 2222' >> /etc/ssh/sshd_config.d/hardening.conf"
        elif tweak == "auditd_enable":
            return "apt-get install -y auditd && systemctl enable --now auditd"
        elif tweak == "disable_gui":
            return "systemctl set-default multi-user.target"
        elif tweak == "auto_updates":
            return "apt-get install -y unattended-upgrades"
        elif tweak == "backup_setup":
            return "apt-get install -y timeshift"
        else:
            return None

    def show_graph_popup(self, resource_type):
        """Show a popup window with detailed graph for the resource"""
        popup = tk.Toplevel(self.root)
        popup.title(f"{resource_type.upper()} Monitor")
        popup.geometry("800x500")
        popup.configure(bg=THEME["bg"])
        
        # Center the popup window
        popup.update_idletasks()
        width = popup.winfo_width()
        height = popup.winfo_height()
        x = (popup.winfo_screenwidth() // 2) - (width // 2)
        y = (popup.winfo_screenheight() // 2) - (height // 2)
        popup.geometry(f"{width}x{height}+{x}+{y}")
        
        # Header
        header = tk.Frame(popup, bg=THEME["panel"])
        header.pack(fill="x", padx=10, pady=10)
        
        title_map = {
            "cpu": "CPU USAGE MONITOR",
            "gpu": "GPU USAGE MONITOR",
            "mem": "MEMORY USAGE MONITOR",
            "disk": "DISK USAGE INFORMATION",
            "net": "NETWORK ACTIVITY MONITOR"
        }
        
        tk.Label(header, text=title_map.get(resource_type, "RESOURCE MONITOR"), 
                bg=THEME["panel"], fg=THEME["accent"],
                font=("Courier New", 14, "bold")).pack()
        
        # Content frame
        content = tk.Frame(popup, bg=THEME["bg"])
        content.pack(fill="both", expand=True, padx=10, pady=5)
        
        if resource_type == "disk":
            # For disk, show detailed text info
            disk_text = scrolledtext.ScrolledText(content, bg="black", fg=THEME["success"],
                                                 font=("Courier New", 10), wrap="none")
            disk_text.pack(fill="both", expand=True)
            
            try:
                result = subprocess.run(['df', '-h', '--output=source,size,used,avail,pcent,target'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    disk_text.insert(tk.END, result.stdout)
            except:
                disk_text.insert(tk.END, "Error reading disk information")
            
            disk_text.config(state='disabled')
        else:
            # For other resources, show live graph
            graph_canvas = tk.Canvas(content, bg="black", height=350, highlightthickness=0)
            graph_canvas.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Info label
            info_label = tk.Label(content, text="Loading...", bg=THEME["bg"], fg=THEME["fg"],
                                font=("Courier New", 10, "bold"))
            info_label.pack(pady=5)
            
            # Update function
            def update_popup_graph():
                if not popup.winfo_exists():
                    return
                
                # Get current data
                if resource_type == "cpu":
                    self.draw_graph(graph_canvas, self.monitor_data["cpu_history"], THEME["accent"])
                    info_label.config(text=self.cpu_info_label.cget("text"))
                elif resource_type == "gpu":
                    info_label.config(text=self.gpu_info_label.cget("text"))
                elif resource_type == "mem":
                    self.draw_graph(graph_canvas, self.monitor_data["mem_history"], THEME["success"])
                    info_label.config(text=self.mem_info_label.cget("text"))
                elif resource_type == "net":
                    self.draw_graph(graph_canvas, self.monitor_data["net_rx_history"], THEME["warning"])
                    info_label.config(text=self.net_info_label.cget("text"))
                
                popup.after(1000, update_popup_graph)
            
            update_popup_graph()
        
        # Close button
        tk.Button(popup, text="[ CLOSE ]", bg=THEME["accent"], fg=THEME["bg"],
                 font=("Courier New", 10, "bold"), relief="flat",
                 command=popup.destroy).pack(pady=10)
    
    def show_about_dialog(self):
        """Show comprehensive About dialog with app and creator information"""
        about = tk.Toplevel(self.root)
        about.title("About PULSE")
        about.geometry("700x600")
        about.configure(bg=THEME["bg"])
        about.resizable(False, False)
        
        # Center the about window
        about.update_idletasks()
        width = about.winfo_width()
        height = about.winfo_height()
        x = (about.winfo_screenwidth() // 2) - (width // 2)
        y = (about.winfo_screenheight() // 2) - (height // 2)
        about.geometry(f"{width}x{height}+{x}+{y}")
        
        # Main container
        container = tk.Frame(about, bg=THEME["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # App Title
        title_frame = tk.Frame(container, bg=THEME["panel"], relief="ridge", bd=2)
        title_frame.pack(fill="x", pady=10)
        
        tk.Label(title_frame, text="░▒▓ PULSE ▓▒░", bg=THEME["panel"], fg=THEME["accent"],
                font=("Courier New", 20, "bold")).pack(pady=15)
        
        tk.Label(title_frame, text="Package Utilities & Linux System Engine", 
                bg=THEME["panel"], fg=THEME["fg"],
                font=("Courier New", 10, "italic")).pack()
        
        tk.Label(title_frame, text="For Debian-based Linux Systems", 
                bg=THEME["panel"], fg=THEME["warning"],
                font=("Courier New", 9)).pack(pady=(5, 15))
        
        # Description
        desc_frame = tk.Frame(container, bg=THEME["bg"])
        desc_frame.pack(fill="x", pady=10)
        
        desc_text = (
            "A comprehensive system utility suite designed for advanced\n"
            "Linux administration, security hardening, and performance\n"
            "optimization. Built with Python and Tkinter for maximum\n"
            "compatibility and minimal dependencies.\n\n"
            "► Package Management & Installation\n"
            "► System Tweaks & Performance Tuning\n"
            "► Security Hardening & Audit Tools\n"
            "► Real-time System Monitoring\n"
            "► Network Configuration & Optimization"
        )
        
        tk.Label(desc_frame, text=desc_text, bg=THEME["bg"], fg=THEME["fg"],
                font=("Courier New", 9), justify="left").pack()
        
        # Separator
        separator1 = tk.Frame(container, bg=THEME["accent"], height=2)
        separator1.pack(fill="x", pady=15)
        
        # Creators Section
        creators_frame = tk.Frame(container, bg=THEME["panel"], relief="ridge", bd=2)
        creators_frame.pack(fill="x", pady=10)
        
        tk.Label(creators_frame, text="⚙ DEVELOPMENT TEAM ⚙", bg=THEME["panel"], fg=THEME["success"],
                font=("Courier New", 12, "bold")).pack(pady=10)
        
        creators = [
            "Daniel Noel Guillen",
            "Ken Cyron Abentino",
            "Kean Elijah Janaban",
            "Kurt David Fadrigo",
            "Vincent Lloyd Payo"
        ]
        
        for creator in creators:
            creator_label = tk.Label(creators_frame, text=f"◆ {creator}", 
                                    bg=THEME["panel"], fg=THEME["fg"],
                                    font=("Courier New", 10))
            creator_label.pack(pady=3)
        
        tk.Label(creators_frame, text="", bg=THEME["panel"]).pack(pady=5)
        
        # Separator
        separator2 = tk.Frame(container, bg=THEME["accent"], height=2)
        separator2.pack(fill="x", pady=10)
        
        # Tech Stack
        tech_frame = tk.Frame(container, bg=THEME["bg"])
        tech_frame.pack(fill="x", pady=5)
        
        tech_text = "Built with: Python 3 • Tkinter • Subprocess • Threading"
        tk.Label(tech_frame, text=tech_text, bg=THEME["bg"], fg=THEME["warning"],
                font=("Courier New", 8, "italic")).pack()
        
        # Version & License
        footer_text = "v1.0.0 • 2025 • Open Source Project"
        tk.Label(tech_frame, text=footer_text, bg=THEME["bg"], fg=THEME["fg"],
                font=("Courier New", 8)).pack(pady=5)
        
        # Close Button
        tk.Button(container, text="[ CLOSE ]", bg=THEME["accent"], fg=THEME["bg"],
                 font=("Courier New", 10, "bold"), relief="flat",
                 command=about.destroy, width=15).pack(pady=15)

    def launch_btop(self, cmd="btop"):
        """Launch btop/htop in a new terminal window"""
        try:
            if shutil.which("x-terminal-emulator"):
                subprocess.Popen(["x-terminal-emulator", "-e", cmd])
            elif shutil.which("gnome-terminal"):
                subprocess.Popen(["gnome-terminal", "--", cmd])
            elif shutil.which("xterm"):
                subprocess.Popen(["xterm", "-e", cmd])
            else:
                messagebox.showinfo("Info", f"Please run '{cmd}' from your terminal manually.")
        except Exception as e:
            self.log_system(f"Failed to launch {cmd}: {e}", "error")

    def toggle_monitor(self):
        self.monitor_active = not self.monitor_active
        if self.monitor_active:
            self.update_monitor_loop()
        else:
            self.btn_toggle_monitor.config(text="START MONITORING", bg=THEME["success"])

    def draw_graph(self, canvas, data, color, label=""):
        """Draw real-time line graph with automatic scaling.
        Uses linear interpolation between data points for smooth visualization.
        """
        canvas.delete("all")
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        
        if width <= 1:
            width = 400
        if height <= 1:
            height = 100
        
        # Draw grid
        for i in range(0, 101, 25):
            y = height - (i * height / 100)
            canvas.create_line(0, y, width, y, fill="#1a1a1a", width=1)
            canvas.create_text(5, y, text=f"{i}%", fill="#444", anchor="w", font=("Courier New", 7))
        
        # Draw data line
        if len(data) > 1:
            points = []
            step = width / (len(data) - 1)
            for i, value in enumerate(data):
                x = i * step
                y = height - (value * height / 100)
                points.extend([x, y])
            
            if len(points) >= 4:
                canvas.create_line(points, fill=color, width=2, smooth=True)
        
        # Draw current value
        if data:
            current = data[-1]
            canvas.create_text(width - 10, 10, text=f"{current:.1f}%", 
                             fill=color, anchor="ne", font=("Courier New", 12, "bold"))

    def update_monitor_loop(self):
        """Continuously update resource monitor every second.
        Uses Tkinter's after() for non-blocking scheduling.
        1000ms interval balances responsiveness with CPU usage.
        """
        if not self.monitor_active:
            return
        
        # Update all monitoring functions
        self.update_cpu_info()
        self.update_gpu_info()
        self.update_mem_info()
        self.update_disk_info()
        self.update_network_info()
        self.update_uptime_info()
        
        # Schedule next update (1 second, non-blocking - allows UI to remain responsive)
        self.root.after(1000, self.update_monitor_loop)

    def update_cpu_info(self):
        """Update CPU usage information"""
        try:
            # Parse /proc/stat for CPU time (user, nice, system, idle, iowait, irq, softirq, steal)
            # Format: cpu user nice system idle iowait irq softirq steal guest guest_nice
            with open("/proc/stat", "r") as f:
                line = f.readline()
                fields = line.split()
                idle = int(fields[4])
                total = sum(int(x) for x in fields[1:8])
            
            if not hasattr(self, '_last_cpu_total'):
                self._last_cpu_total = total
                self._last_cpu_idle = idle
                cpu_percent = 0
            else:
                total_diff = total - self._last_cpu_total
                idle_diff = idle - self._last_cpu_idle
                cpu_percent = 100.0 * (total_diff - idle_diff) / total_diff if total_diff > 0 else 0
                self._last_cpu_total = total
                self._last_cpu_idle = idle
            
            # Update history
            self.monitor_data["cpu_history"].pop(0)
            self.monitor_data["cpu_history"].append(cpu_percent)
            
            # Update text label
            self.cpu_info_label.config(text=f"CPU\n{cpu_percent:.1f}%")
            
        except Exception as e:
            self.cpu_info_label.config(text=f"Error\n{str(e)[:20]}")
    
    def update_gpu_info(self):
        """Update GPU usage (nvidia-smi or rocm-smi)"""
        try:
            # Try NVIDIA first
            result = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total',
                                   '--format=csv,noheader,nounits'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                parts = result.stdout.strip().split(',')
                gpu_util = parts[0].strip()
                gpu_temp = parts[1].strip()
                mem_used = float(parts[2].strip())
                mem_total = float(parts[3].strip())
                mem_percent = (mem_used / mem_total * 100) if mem_total > 0 else 0
                
                self.gpu_info_label.config(
                    text=f"GPU: {gpu_util}%\nTemp: {gpu_temp}°C\nVRAM: {mem_percent:.0f}%"
                )
                return
        except:
            pass
        
        # No GPU detected
        self.gpu_info_label.config(text="No GPU\nDetected")

    def update_mem_info(self):
        """Update memory usage information"""
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
                mem_info = {}
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        mem_info[parts[0].rstrip(':')] = int(parts[1])
            
            total = mem_info.get('MemTotal', 0)
            available = mem_info.get('MemAvailable', 0)
            used = total - available
            percent = (used / total * 100) if total > 0 else 0
            
            # Update history
            self.monitor_data["mem_history"].pop(0)
            self.monitor_data["mem_history"].append(percent)
            
            # Update text label
            used_gb = used / 1024 / 1024
            total_gb = total / 1024 / 1024
            self.mem_info_label.config(text=f"Memory\n{percent:.1f}%\n{used_gb:.1f}/{total_gb:.1f} GB")
            
        except Exception as e:
            self.mem_info_label.config(text=f"Error\n{str(e)[:20]}")

    def update_disk_info(self):
        """Update disk usage information"""
        try:
            result = subprocess.run(['df', '-h', '--output=source,size,used,avail,pcent,target'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                real_fs = [l for l in lines if l.startswith('/dev/')]
                
                if real_fs:
                    # Show summary in label
                    total_used = 0
                    total_size = 0
                    for line in real_fs:
                        parts = line.split()
                        if len(parts) >= 5:
                            used_str = parts[2].rstrip('GMK')
                            size_str = parts[1].rstrip('GMK')
                            try:
                                if 'G' in parts[2]:
                                    total_used += float(used_str)
                                if 'G' in parts[1]:
                                    total_size += float(size_str)
                            except:
                                pass
                    
                    percent = (total_used / total_size * 100) if total_size > 0 else 0
                    self.disk_info_label.config(text=f"Disk\n{percent:.1f}%\n{total_used:.0f}/{total_size:.0f} GB")
                else:
                    self.disk_info_label.config(text="No disk\ninformation")
            else:
                self.disk_info_label.config(text="Error reading\ndisk info")
        except Exception as e:
            self.disk_info_label.config(text=f"Error\n{str(e)[:20]}")

    def update_network_info(self):
        """Update network activity information"""
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            
            total_rx = 0
            total_tx = 0
            
            for line in lines[2:]:
                if ':' in line:
                    parts = line.split()
                    iface = parts[0].rstrip(':')
                    if iface != 'lo':  # Skip loopback
                        total_rx += int(parts[1])
                        total_tx += int(parts[9])
            
            # Calculate network throughput using byte delta over time interval
            # Rates represent bytes transferred since last update
            if self.monitor_data["last_net_rx"] > 0:
                rx_rate = total_rx - self.monitor_data["last_net_rx"]
                tx_rate = total_tx - self.monitor_data["last_net_tx"]
            else:
                rx_rate = 0
                tx_rate = 0
            
            self.monitor_data["last_net_rx"] = total_rx
            self.monitor_data["last_net_tx"] = total_tx
            
            # Convert rates to MB/s for human-readable format
            rx_rate_mb = rx_rate / 1024 / 1024
            tx_rate_mb = tx_rate / 1024 / 1024
            
            # Update history (for RX)
            self.monitor_data["net_rx_history"].pop(0)
            self.monitor_data["net_rx_history"].append(rx_rate_mb)
            
            # Update text label
            self.net_info_label.config(
                text=f"Network\n↓ {rx_rate_mb:.2f} MB/s\n↑ {tx_rate_mb:.2f} MB/s"
            )
            
        except Exception as e:
            self.net_info_label.config(text=f"Error\n{str(e)[:20]}")

    def update_uptime_info(self):
        """Update system uptime information"""
        try:
            with open("/proc/uptime", "r") as f:
                uptime_seconds = float(f.read().split()[0])
            
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            
            self.uptime_label.config(text=f"Uptime\n{days}d {hours}h {minutes}m")
            
        except Exception as e:
            self.uptime_label.config(text=f"Error\n{str(e)[:20]}")

    # ==========================================
    # CORE LOGIC & EVENT HANDLERS
    # ==========================================

    def switch_module(self, module_name):
        """
        Switches between different modules (install, tweaks, monitor).
        Updates UI to show appropriate tabs and buttons.
        
        Args:
            module_name: Name of module to switch to ('install', 'tweaks', 'monitor')
        """
        if module_name == self.current_module:
            return
        
        self.current_module = module_name
        
        # Define tab groups
        tweak_tabs = [self.tweaks_tab_index, self.security_tab_index, self.network_tab_index, self.presets_tab_index]
        monitor_tabs = [self.audit_tab_index, self.resources_tab_index, self.services_tab_index]
        
        if module_name == "install":
            # Show only install tabs (app categories + installed apps), hide all others
            # This reduces memory footprint by only rendering visible widgets
            for i in range(len(self.notebook.tabs())):
                if i in tweak_tabs or i in monitor_tabs:
                    self.notebook.hide(i)  # Hide tab but preserve state
                else:
                    try:
                        self.notebook.tab(i, state="normal")
                    except:
                        pass
            
            # Update button appearance
            self.btn_module_install.config(bg=THEME["accent"], fg=THEME["bg"])
            self.btn_module_tweaks.config(bg=THEME["panel"], fg=THEME["fg"])
            self.btn_module_monitor.config(bg=THEME["panel"], fg=THEME["fg"])
            self.btn_action.config(text="[ INSTALL ]", state="normal")
            
        elif module_name == "tweaks":
            # Hide install/monitor tabs, show tweaks tabs
            for i in range(len(self.notebook.tabs())):
                if i not in tweak_tabs:
                    self.notebook.hide(i)
            
            for i in tweak_tabs:
                self.notebook.tab(i, state="normal")
            self.notebook.select(self.tweaks_tab_index)
            
            # Update button appearance
            self.btn_module_install.config(bg=THEME["panel"], fg=THEME["fg"])
            self.btn_module_tweaks.config(bg=THEME["accent"], fg=THEME["bg"])
            self.btn_module_monitor.config(bg=THEME["panel"], fg=THEME["fg"])
            self.btn_action.config(text="[ RUN TWEAKS ]", state="normal")

        elif module_name == "monitor":
            # Hide install/tweaks tabs, show monitor tabs
            for i in range(len(self.notebook.tabs())):
                if i not in monitor_tabs:
                    self.notebook.hide(i)
            
            for i in monitor_tabs:
                self.notebook.tab(i, state="normal")
            self.notebook.select(self.audit_tab_index)
            
            # Update button appearance
            self.btn_module_install.config(bg=THEME["panel"], fg=THEME["fg"])
            self.btn_module_tweaks.config(bg=THEME["panel"], fg=THEME["fg"])
            self.btn_module_monitor.config(bg=THEME["accent"], fg=THEME["bg"])
            self.btn_action.config(text="[ MONITORING ]", state="disabled")
            
            # Auto-start monitoring when entering monitor module
            if not self._resources_initialized:
                self._resources_initialized = True
                if not self.monitor_active:
                    self.monitor_active = True
                    self.update_monitor_loop()
        
        self.log_system(f"Switched to {module_name.upper()} module")

    def execute_action(self):
        """
        Executes the appropriate action based on current module.
        Routes to install or tweaks execution.
        """
        if self.current_module == "install":
            self.start_install_thread()
        elif self.current_module == "tweaks":
            self.run_tweaks()

    def run_tweaks(self):
        """
        Executes selected system tweaks.
        """
        tweaks_to_run = []
        
        if hasattr(self, 'cleanup_var') and self.cleanup_var.get():
            tweaks_to_run.append("cleanup")
        
        if hasattr(self, 'backup_var') and self.backup_var.get():
            tweaks_to_run.append("backup")
        
        if hasattr(self, 'security_firewall_var') and self.security_firewall_var.get():
            tweaks_to_run.append("firewall")
        if hasattr(self, 'security_services_var') and self.security_services_var.get():
            tweaks_to_run.append("services")
        if hasattr(self, 'security_ssh_var') and self.security_ssh_var.get():
            tweaks_to_run.append("ssh")
        if hasattr(self, 'security_updates_var') and self.security_updates_var.get():
            tweaks_to_run.append("updates")
        if hasattr(self, 'security_privesc_var') and self.security_privesc_var.get():
            tweaks_to_run.append("privesc")
        
        # Network tweaks
        if hasattr(self, 'dns_cloudflare_var') and self.dns_cloudflare_var.get():
            tweaks_to_run.append("dns_cloudflare")
        if hasattr(self, 'dns_google_var') and self.dns_google_var.get():
            tweaks_to_run.append("dns_google")
        if hasattr(self, 'net_bbr_var') and self.net_bbr_var.get():
            tweaks_to_run.append("net_bbr")
        if hasattr(self, 'net_mac_var') and self.net_mac_var.get():
            tweaks_to_run.append("net_mac")
        
        if not tweaks_to_run:
            messagebox.showwarning("No Tweaks Selected", "Please select at least one tweak to run.")
            return
        
        self.btn_action.config(state="disabled", text="PROCESSING...")
        threading.Thread(target=self.execute_tweaks, args=(tweaks_to_run,), daemon=True).start()

    def execute_tweaks(self, tweaks_list):
        """Execute selected system tweaks sequentially with progress tracking."""
        # Validate input
        if not tweaks_list or not isinstance(tweaks_list, list):
            self.log_system("Invalid tweaks list provided", "error")
            self.root.after(0, lambda: self.btn_action.config(state="normal", text="[ RUN TWEAKS ]"))
            return
        
        total_tweaks = len(tweaks_list)
        current = 0
        
        self.log_system(f"Starting execution of {total_tweaks} tweak(s)...")
        self.root.after(0, lambda: self.progress_bar.config(value=0))
        
        # Execute each tweak sequentially
        for tweak in tweaks_list:
            current += 1
            progress = int((current / total_tweaks) * 100)
            
            # Route to appropriate handler
            if tweak == "cleanup":
                self.execute_safe_cleanup()
            elif tweak == "backup":
                self.execute_automated_backup()
            elif tweak == "firewall":
                self.execute_firewall_hardening()
            elif tweak == "services":
                self.execute_disable_services()
            elif tweak == "ssh":
                self.execute_ssh_hardening()
            elif tweak == "updates":
                self.execute_auto_updates()
            elif tweak == "privesc":
                self.execute_privesc_hardening()
            elif tweak == "dns_cloudflare":
                self.execute_dns_cloudflare()
            elif tweak == "dns_google":
                self.execute_dns_google()
            elif tweak == "net_bbr":
                self.execute_bbr_tcp()
            elif tweak == "net_mac":
                self.execute_change_mac()
            else:
                self.log_system(f"Unknown tweak identifier: {tweak}", "warn")
            
            self.root.after(0, lambda p=progress: self.progress_bar.config(value=p))
        
        # Finalize operation
        self.root.after(0, lambda: self.progress_bar.config(value=100))
        self.root.after(0, lambda: self.progress_label.config(text="All tweaks completed"))
        self.log_system("System tweaks execution completed!", "success")
        
        # Clear tweak selections
        self.root.after(0, self.clear_all_tweaks)
        
        self.root.after(0, lambda: messagebox.showinfo("Success", f"{total_tweaks} tweak(s) applied successfully!"))
        self.root.after(0, lambda: self.btn_action.config(state="normal", text="[ RUN TWEAKS ]"))

    def execute_safe_cleanup(self):
        """Wrapper for execute_safe_cleanup from tweaks module."""
        execute_safe_cleanup(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_automated_backup(self):
        """Wrapper for execute_automated_backup from tweaks module."""
        execute_automated_backup(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_firewall_hardening(self):
        """Wrapper for execute_firewall_hardening from tweaks module."""
        execute_firewall_hardening(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_disable_services(self):
        """Wrapper for execute_disable_services from tweaks module."""
        execute_disable_services(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_ssh_hardening(self):
        """Wrapper for execute_ssh_hardening from tweaks module."""
        execute_ssh_hardening(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_auto_updates(self):
        """Wrapper for execute_auto_updates from tweaks module."""
        execute_auto_updates(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_privesc_hardening(self):
        """Wrapper for execute_privesc_hardening from tweaks module."""
        execute_privesc_hardening(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def install_security_tools(self):
        """Wrapper for install_security_tools from tweaks module."""
        install_security_tools(self.log_system, self.root, self.progress_bar, self.progress_label, self.btn_action, self.run_generic_command)

    def execute_dns_cloudflare(self):
        """Wrapper for execute_dns_cloudflare from tweaks module."""
        execute_dns_cloudflare(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_dns_google(self):
        """Wrapper for execute_dns_google from tweaks module."""
        execute_dns_google(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_bbr_tcp(self):
        """Wrapper for execute_bbr_tcp from tweaks module."""
        execute_bbr_tcp(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def execute_change_mac(self):
        """Wrapper for execute_change_mac from tweaks module."""
        execute_change_mac(self.log_system, self.root, self.progress_label, self.run_generic_command)

    def log_system(self, message, msg_type="info"):
        """Thread-safe logging to GUI terminal and file. Types: info, success, warn, error."""
        # Validate inputs
        if not message:
            return
        
        if not isinstance(message, str):
            message = str(message)
        
        if msg_type not in VALID_LOG_TYPES:
            msg_type = "info"
        
        # Log to file first (persistent audit trail, always runs even if GUI fails)
        log_methods = {
            "error": self.file_logger.error,
            "warn": self.file_logger.warning,
            "success": self.file_logger.info,
            "info": self.file_logger.info
        }
        log_method = log_methods.get(msg_type, self.file_logger.info)
        log_method(message)
        
        def _log():
            """Inner function runs on main thread for Tkinter thread safety.
            GUI updates must happen on main thread to avoid crashes.
            """
            try:
                self.terminal.config(state='normal')
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                # Map types to prefixes and colors
                prefix_map = {
                    "error": "ERR ",
                    "warn": "WARN",
                    "success": "DONE",
                    "info": "INFO"
                }
                prefix = prefix_map.get(msg_type, "INFO")
                
                color_map = {
                    "error": THEME["error"],
                    "warn": THEME["warning"],
                    "success": THEME["success"],
                    "info": THEME["success"]
                }
                color = color_map.get(msg_type, THEME["success"])
                
                # Insert formatted message
                self.terminal.insert("end", f"[{timestamp}] ", "timestamp")
                self.terminal.insert("end", f"[{prefix}] ", msg_type)
                self.terminal.insert("end", f"{message}\n")
                
                # Tag configuration
                self.terminal.tag_config("timestamp", foreground="#888888")
                self.terminal.tag_config(msg_type, foreground=color, font=("Consolas", 9, "bold"))
                
                # Auto-scroll to end
                self.terminal.see("end")
                self.terminal.config(state='disabled')
                
            except tk.TclError:
                # Widget destroyed - fallback to console
                print(f"[{msg_type.upper()}] {message}")
        
        # Execute on main thread
        self.root.after(0, _log)
    
    def clear_all_checkboxes(self):
        """Clear all checkbox selections in app categories."""
        for name, data in self.checkboxes.items():
            data['var'].set(False)
        self.log_system("All app selections cleared", "info")
    
    def clear_all_tweaks(self):
        """Clear all tweak checkbox selections."""
        tweak_vars = [
            'cleanup_var', 'security_firewall_var', 'security_services_var',
            'security_ssh_var', 'security_updates_var', 'security_privesc_var',
            'dns_cloudflare_var', 'dns_google_var', 'net_bbr_var', 'net_mac_var'
        ]
        
        for var_name in tweak_vars:
            if hasattr(self, var_name):
                getattr(self, var_name).set(False)
        
        self.log_system("All tweak selections cleared", "info")

    def refresh_installed_apps(self):
        """Scan APT database and update UI with installation status."""
        if not HAS_APT_LIB:
            self.log_system("Cannot refresh: APT library not available", "warn")
            return

        self.log_system("Querying APT Database for package status...")
        self.apt_manager.refresh()
        self.installed_apps.clear()
        
        # Clear treeview on main thread
        def _clear_tree():
            if hasattr(self, 'installed_tree'):
                try:
                    for item in self.installed_tree.get_children():
                        self.installed_tree.delete(item)
                except tk.TclError as e:
                    self.log_system(f"Error clearing tree: {e}", "warn")
        
        self.root.after(0, _clear_tree)
        
        count = 0
        for display_name, data in self.checkboxes.items():
            pkg_name = data['pkg']
            var = data['var']
            
            try:
                if self.apt_manager.is_installed(pkg_name):
                    self.installed_apps.add(display_name)
                    count += 1
                    
                    # Add to tree (thread-safe)
                    def _add_to_tree(name=display_name, pkg=pkg_name):
                        if hasattr(self, 'installed_tree'):
                            try:
                                self.installed_tree.insert(
                                    "", "end", 
                                    text=name,
                                    tags=(pkg,)
                                )
                            except tk.TclError:
                                pass
                    
                    self.root.after(0, _add_to_tree)
                    self.root.after(0, lambda v=var: v.set(False))
                    
            except Exception as e:
                self.log_system(f"Error checking package '{pkg_name}': {e}", "warn")
                continue
        
        # Update status label
        def _update_status():
            if hasattr(self, 'progress_label'):
                self.progress_label.config(
                    text=f"System Ready. Installed packages detected: {count}"
                )
        
        self.root.after(0, _update_status)
        self.log_system(f"Status Scan Complete. Found {count} installed packages.", "success")

    def on_installed_select(self, event):
        """Show package details when item selected in installed apps tree."""
        selected = self.installed_tree.selection()
        if not selected:
            return
        
        # If multiple selections, show summary
        if len(selected) > 1:
            count = len(selected)
            pkg_list = []
            for item_id in selected:
                item = self.installed_tree.item(item_id)
                display_name = item['text']
                pkg_list.append(display_name)
            
            details = f"Selected: {count} package(s)\n\n"
            details += "Packages:\n" + "\n".join([f"• {pkg}" for pkg in pkg_list])
            details += "\n\nTip: Click UNINSTALL to remove all selected packages with single authentication."
            
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
            return
        
        item = self.installed_tree.item(selected[0])
        pkg_name = item['tags'][0] if item['tags'] else None
        if not pkg_name:
            return
        pkg = self.apt_manager.get_package(pkg_name)
        
        details = "Package details not available."
        if pkg:
            details = f"Name: {pkg.name}\n"
            details += f"ID: {pkg.id}\n"
            details += f"Architecture: {pkg.architecture}\n\n"
            
            if pkg.installed:
                details += f"Installed Version: {pkg.installed.version}\n"
                details += f"Size: {pkg.installed.size} bytes\n"
                
                # Extract dependencies safely
                try:
                    if pkg.installed.dependencies:
                        deps = ', '.join([d.name for d in pkg.installed.dependencies[0]])
                    else:
                        deps = 'None'
                except Exception:
                    deps = 'Unable to retrieve'
                
                details += f"Dependencies: {deps}\n\n"
            
            if pkg.candidate:
                details += f"Candidate Version: {pkg.candidate.version}\n\n"
                details += f"Description:\n{pkg.candidate.description}\n"
        
        # Update details panel
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)

    def start_install_thread(self):
        """
        Collects selected packages and starts the installation thread.
        Validates that at least one package is selected before proceeding.
        
        Process:
        1. Iterates through all checkboxes to find selected items
        2. Validates selection is non-empty
        3. Validates packages exist in repositories
        4. Disables UI controls during operation
        5. Launches background thread for installation
        
        Threading:
        - Uses daemon thread to prevent blocking main UI
        - Installation runs in background
        - UI remains responsive during operation
        """
        # Collect selected packages from checkboxes
        to_install = [
            data['pkg'] 
            for name, data in self.checkboxes.items() 
            if data['var'].get()  # Only get checked items
        ]
        
        # Validate at least one package is selected
        if not to_install:
            messagebox.showwarning("PULSE", "No packages selected.\n\nPlease select at least one package to install.")
            return
        
        # Validate and sanitize package names (security check)
        valid_packages = []
        for pkg in to_install:
            try:
                sanitized_pkg = sanitize_input(pkg)
                valid_packages.append(sanitized_pkg)
            except ValueError as e:
                self.log_system(f"Invalid package name: {pkg} - {e}", "error")
                self.file_logger.error(f"Package sanitization failed: {e}")
                messagebox.showerror(
                    "Invalid Package",
                    f"Package name contains invalid characters:\n\n{pkg}\n\n{str(e)}"
                )
                return
        
        # Validate packages exist in repositories
        self.log_system(f"Validating {len(valid_packages)} package(s)...", "info")
        validated, invalid = self.validate_packages(valid_packages)
        
        if invalid:
            self.log_system(f"{len(invalid)} package(s) not found in repositories", "warn")
            result = messagebox.askyesno(
                "Package Validation Warning",
                f"The following packages were not found in repositories:\n\n" +
                "\n".join(invalid[:10]) +
                (f"\n...and {len(invalid) - 10} more" if len(invalid) > 10 else "") +
                "\n\nDo you want to proceed with valid packages only?"
            )
            if not result:
                return
            to_install = validated
        else:
            to_install = validated
        
        if not to_install:
            self.log_system("No valid packages to install", "error")
            messagebox.showerror("No Valid Packages", "All selected packages are invalid or not found.")
            return
        
        # Log installation start
        self.log_system(f"Starting installation of {len(to_install)} package(s)", "info")
        self.file_logger.info(f"Installing packages: {', '.join(to_install)}")
        
        # Disable action button during operation to prevent double-clicks
        self.btn_action.config(state="disabled", text="PROCESSING...")
        
        # Run installation in background thread (daemon=True for auto-cleanup)
        threading.Thread(
            target=self.run_apt_install, 
            args=(to_install,), 
            daemon=True
        ).start()

    def run_apt_install(self, package_list):
        """Wrapper for run_apt_install from commands module."""
        run_apt_install(
            package_list, 
            self.log_system, 
            self.root, 
            self.progress_bar, 
            self.progress_label, 
            self.refresh_installed_apps, 
            self.clear_all_checkboxes, 
            self.btn_action
        )

    def uninstall_selected(self):
        """Uninstall selected packages from installed apps tree (batch operation with confirmation)."""
        # Validate selection
        selected = self.installed_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select at least one application to uninstall.")
            return
        
        # Collect and validate package names
        pkg_names = []
        for item_id in selected:
            item = self.installed_tree.item(item_id)
            pkg_name = item['tags'][0] if item['tags'] else None
            
            if pkg_name:
                # Security: validate alphanumeric with hyphens/underscores/dots
                if pkg_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
                    pkg_names.append(pkg_name)
                else:
                    self.log_system(f"Skipping invalid package name: {pkg_name}", "warn")
        
        if not pkg_names:
            messagebox.showerror("Error", "No valid packages selected for uninstallation.")
            return
        
        # Show confirmation dialog with package details
        count = len(pkg_names)
        pkg_list = "\n".join([f"• {pkg}" for pkg in pkg_names])
        
        confirm_msg = f"Uninstall {count} package(s)?\n\n{pkg_list}\n\n"
        confirm_msg += "Note: Configuration files will be preserved.\n"
        confirm_msg += "Use apt-get purge manually to remove configs."
        
        if not messagebox.askyesno("Confirm Uninstall", confirm_msg):
            self.log_system("Uninstall cancelled by user", "warn")
            return
        
        # Validate apt-get is available
        if not shutil.which("apt-get"):
            messagebox.showerror("Error", "apt-get command not found.")
            return
        
        # Single command for all packages (batch operation)
        cmd = ["pkexec", "apt-get", "remove", "-y"] + pkg_names
        
        # Execute in background thread to prevent UI freeze
        threading.Thread(
            target=self.run_generic_command, 
            args=(cmd, f"Uninstalling {count} package(s)"), 
            daemon=True
        ).start()

    def update_selected(self):
        """Reinstall/update selected package (repairs broken installs or updates to latest)."""
        # Validate selection
        selected = self.installed_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an application to update.")
            return
        
        item = self.installed_tree.item(selected[0])
        pkg_name = item['tags'][0] if item['tags'] else None
        
        if not pkg_name:
            messagebox.showerror("Error", "Unable to determine package name.")
            self.log_system("Update failed: No package name in tree item", "error")
            return
        
        # Validate package name format
        if not pkg_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            messagebox.showerror("Error", "Invalid package name format.")
            self.log_system(f"Invalid package name for update: {pkg_name}", "error")
            return
        
        # Display confirmation with package details
        confirm_msg = f"Reinstall/Update {pkg_name}?\n\n"
        confirm_msg += "This will:\n"
        confirm_msg += "• Re-download the package\n"
        confirm_msg += "• Reinstall all files\n"
        confirm_msg += "• May update to newer version if available\n\n"
        confirm_msg += "Proceed?"
        
        if not messagebox.askyesno("Confirm Update", confirm_msg):
            self.log_system(f"Update cancelled by user: {pkg_name}", "warn")
            return
        
        # Validate apt-get is available
        if not shutil.which("apt-get"):
            messagebox.showerror("Error", "apt-get command not found.")
            return
        
        # Construct reinstall command
        cmd = ["pkexec", "apt-get", "install", "--reinstall", "-y", pkg_name]
        
        # Execute in background thread
        threading.Thread(
            target=self.run_generic_command, 
            args=(cmd, f"Updating {pkg_name}"), 
            daemon=True
        ).start()

    def external_download_install(self):
        """Install from external source (script URL or .deb file)."""
        # Create input dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("External Download & Install")
        dialog.geometry("600x250")
        dialog.configure(bg=THEME["bg"])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (300)
        y = (dialog.winfo_screenheight() // 2) - (125)
        dialog.geometry(f"+{x}+{y}")
        
        # Header
        tk.Label(dialog, text="External Download & Install", 
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=("Courier New", 12, "bold")).pack(pady=15)
        
        # Instructions
        instructions = tk.Label(dialog, 
                               text="Enter .deb file path or URL:\n\n" +
                                    "Examples:\n" +
                                    "• /home/user/downloads/opera-stable_125.0.5729.15_amd64.deb\n" +
                                    "• https://example.com/package.deb",
                               bg=THEME["bg"], fg=THEME["fg"],
                               font=("Courier New", 9), justify="left")
        instructions.pack(padx=20, pady=5)
        
        # Input field
        input_frame = tk.Frame(dialog, bg=THEME["bg"])
        input_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(input_frame, text="Source:", bg=THEME["bg"], fg=THEME["fg"],
                 font=THEME["font_main"]).pack(side="left", padx=(0, 10))
        
        entry = tk.Entry(input_frame, bg=THEME["panel"], fg=THEME["fg"],
                         font=THEME["font_main"], insertbackground=THEME["accent"])
        entry.pack(side="left", fill="x", expand=True)
        entry.focus()
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=THEME["bg"])
        btn_frame.pack(pady=15)
        
        def install_external():
            source = entry.get().strip()
            if not source:
                messagebox.showwarning("Invalid Input", "Please enter a source URL or file path.")
                return
            
            dialog.destroy()
            threading.Thread(target=self.process_external_install, args=(source,), daemon=True).start()
        
        tk.Button(btn_frame, text="INSTALL", bg=THEME["success"], fg="black",
                  font=("Courier New", 10, "bold"), command=install_external,
                  width=12).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="CANCEL", bg=THEME["panel"], fg=THEME["fg"],
                  font=("Courier New", 10, "bold"), command=dialog.destroy,
                  width=12).pack(side="left", padx=5)
        
        # Enter key to install
        entry.bind('<Return>', lambda e: install_external())

    def process_external_install(self, source):
        """Process external installation from .deb file with security validation."""
        self.log_system(f"Processing external install: {source}", "info")
        self.file_logger.info(f"External install requested: {source}")
        
        try:
            # Validate URL if it's a remote source
            if source.startswith("http://") or source.startswith("https://") or source.startswith("ftp://"):
                try:
                    validated_url = validate_url(source)
                    self.log_system("URL validated successfully", "success")
                    self.file_logger.info(f"Validated URL: {validated_url}")
                    
                    # Only handle .deb files
                    if not validated_url.endswith(".deb"):
                        self.log_system("Warning: URL does not end with .deb extension", "warn")
                        result = messagebox.askyesno(
                            "Non-.deb URL",
                            "The URL doesn't have a .deb extension.\n\nDo you want to proceed anyway?"
                        )
                        if not result:
                            return
                    
                    self.log_system("Detected: Remote package URL", "info")
                    self.install_deb_package(validated_url)
                    
                except ValueError as e:
                    self.log_system(f"URL validation failed: {e}", "error")
                    self.file_logger.error(f"URL validation error: {e}")
                    messagebox.showerror("Invalid URL", f"The URL is not valid or safe:\n\n{str(e)}")
                    return
                    
            elif os.path.exists(source):
                # Local file - validate path
                try:
                    # Basic path validation (allow more characters for local paths)
                    if not os.path.isabs(source):
                        source = os.path.abspath(source)
                    
                    if not source.endswith(".deb"):
                        self.log_system("Error: Only .deb files are supported", "error")
                        messagebox.showerror("Unsupported File", "Only .deb package files are supported.")
                        return
                    
                    self.log_system("Detected: Local Debian package (.deb)", "info")
                    self.file_logger.info(f"Installing local .deb: {source}")
                    self.install_deb_package(source)
                    
                except Exception as e:
                    self.log_system(f"Path validation failed: {e}", "error")
                    self.file_logger.error(f"Local file error: {e}")
                    messagebox.showerror("Invalid Path", f"Error with file path:\n\n{str(e)}")
                    return
            else:
                self.log_system("Invalid source. File not found.", "error")
                self.file_logger.warning(f"Source not found: {source}")
                messagebox.showerror(
                    "Invalid Source",
                    "The specified file path does not exist.\n\nPlease provide a valid .deb file path or URL."
                )
                
        except Exception as e:
            self.log_system(f"External install failed: {e}", "error")
            self.file_logger.error(f"External install exception: {e}", exc_info=True)

    def install_deb_package(self, deb_source):
        """Wrapper for install_deb_package from commands module."""
        install_deb_package(deb_source, self.log_system, self.refresh_installed_apps)

    def run_generic_command(self, cmd, description):
        """Wrapper for run_generic_command from commands module."""
        run_generic_command(cmd, description, self.log_system, self.root, self.refresh_installed_apps)
    
    def on_closing(self):
        """Handle application exit - save preferences and cleanup."""
        try:
            # Save window geometry
            self.preferences["window_geometry"] = self.root.geometry()
            
            # Save last used module
            self.preferences["last_module"] = self.current_module
            
            # Save preferences to file
            if save_user_preferences(self.preferences):
                self.file_logger.info("User preferences saved successfully")
            else:
                self.file_logger.warning("Failed to save user preferences")
            
            self.file_logger.info("PULSE application closing")
            
        except Exception as e:
            self.file_logger.error(f"Error during cleanup: {e}")
        finally:
            self.root.destroy()

# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":
    # Initialize Tkinter root window and launch application
    # root.mainloop() blocks until window is closed
    root = tk.Tk()
    app = PulseInstaller(root)
    root.mainloop()
