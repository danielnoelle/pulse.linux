#!/usr/bin/env python3
import threading

# ==========================================
# DEPENDENCIES CHECK
# ==========================================

# Try importing python-apt, essential for package management intelligence
try:
    import apt
    HAS_APT_LIB = True
except ImportError:
    HAS_APT_LIB = False
    print("WARNING: python3-apt not found. Install with: sudo apt install python3-apt")


class AptManager:
    """Thread-safe APT cache manager. Prevents race conditions in package queries."""
    
    def __init__(self, log_callback):
        """Initialize with logging callback."""
        self.cache = None
        self.lock = threading.Lock()
        self.log = log_callback

    def initialize(self):
        """Load APT package database. Run in background thread (slow operation)."""
        if not HAS_APT_LIB:
            self.log("APT library not available. Functionality limited.", "error")
            return

        self.log("Initializing APT Cache (Reading package lists)...")
        try:
            with self.lock:
                self.cache = apt.Cache()
            
            if self.cache is None:
                self.log("Cache initialization returned None", "error")
                return
                
            cache_size = len(self.cache)
            if cache_size == 0:
                self.log("Warning: Cache loaded but contains 0 packages", "warn")
            else:
                self.log(f"Cache Loaded. {cache_size} packages available.", "success")
        except PermissionError as e:
            self.log(f"Permission denied loading APT cache: {e}", "error")
        except ImportError as e:
            self.log(f"APT library import error: {e}", "error")
        except Exception as e:
            self.log(f"Failed to load APT cache: {type(e).__name__}: {e}", "error")

    def refresh(self):
        """Reload cache to reflect system changes (call after install/remove)."""
        if not self.cache:
            self.log("Cannot refresh: Cache not initialized", "warn")
            return
        
        try:
            with self.lock:
                self.cache.open(None)
            self.log("Cache refreshed successfully", "success")
        except PermissionError as e:
            self.log(f"Permission denied refreshing cache: {e}", "error")
        except Exception as e:
            self.log(f"Error refreshing cache: {type(e).__name__}: {e}", "error")

    def get_package(self, pkg_name):
        """Get package object by name. Returns None if not found."""
        if not pkg_name or not isinstance(pkg_name, str):
            return None
            
        if not self.cache:
            return None
            
        try:
            if pkg_name in self.cache:
                return self.cache[pkg_name]
        except (KeyError, TypeError) as e:
            self.log(f"Error accessing package '{pkg_name}': {e}", "error")
        
        return None

    def is_installed(self, pkg_name):
        """Check if package is installed. Returns False if not found or error."""
        try:
            pkg = self.get_package(pkg_name)
            if pkg and hasattr(pkg, 'is_installed'):
                return bool(pkg.is_installed)
        except (AttributeError, TypeError) as e:
            self.log(f"Error checking installation status for '{pkg_name}': {e}", "error")
        
        return False
