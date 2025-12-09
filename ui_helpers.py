#!/usr/bin/env python3
import tkinter as tk


class ToolTip:
    """Shows package descriptions on hover. Auto-positions near cursor."""
    
    def __init__(self, widget):
        """Initialize tooltip for widget."""
        if not widget:
            raise ValueError("Widget cannot be None")
        
        self.widget = widget
        self.tipwindow = None
        self.text = None

    def showtip(self, text):
        """Display tooltip text at cursor position."""
        # Validate input
        if not text or not isinstance(text, str):
            return
        
        self.text = text
        
        if self.tipwindow or not self.text:
            return
        
        try:
            # Position tooltip near cursor (27px offset)
            x, y, cx, cy = self.widget.bbox("insert")
            x = x + self.widget.winfo_rootx() + 27
            y = y + cy + self.widget.winfo_rooty() + 27
            
            # Create borderless tooltip window
            self.tipwindow = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(1)
            tw.wm_geometry(f"+{x}+{y}")
            
            label = tk.Label(
                tw, 
                text=self.text, 
                justify=tk.LEFT,
                background="#ffffe0",
                relief=tk.SOLID,
                borderwidth=1,
                font=("tahoma", "8", "normal")
            )
            label.pack(ipadx=1)
            
        except tk.TclError:
            self.hidetip()
            
        except Exception as e:
            # Unexpected error - log but don't crash
            print(f"Tooltip error: {e}")
            self.hidetip()

    def hidetip(self):
        """Destroy tooltip window."""
        tw = self.tipwindow
        self.tipwindow = None
        
        if tw:
            try:
                tw.destroy()
            except tk.TclError:
                pass


def create_tooltip(widget, text_getter):
    """Attach tooltip to widget. text_getter() returns dynamic tooltip text."""
    if not widget:
        raise ValueError("Widget cannot be None")
    
    if not callable(text_getter):
        raise ValueError("text_getter must be callable")
    
    tool_tip = ToolTip(widget)
    
    def enter(event):
        try:
            text = text_getter()
            if text:
                tool_tip.showtip(text)
        except Exception as e:
            print(f"Tooltip text_getter error: {e}")
    
    def leave(event):
        tool_tip.hidetip()
    
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)
