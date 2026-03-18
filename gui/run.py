"""
ThreatKill GUI - Malware & Rootkit Removal Tool
By - RAVI CHAUHAN | github.com/Ravirazchauhan
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import platform
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.scanner import ThreatScanner, ScanResult, Threat, remove_threat

# ── Colours ───────────────────────────────────────────────────────────────────
BG       = "#0b0c10"
SURFACE  = "#111318"
SURFACE2 = "#181b22"
BORDER   = "#1e2330"
ACCENT   = "#00e5ff"
GREEN    = "#00e676"
YELLOW   = "#ffd740"
RED      = "#ff3d5a"
ORANGE   = "#ff6d00"
TEXT     = "#e8eaf0"
MUTED    = "#4a5068"

FONT_MONO  = ("Courier New", 10)
FONT_UI    = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_HEAD  = ("Segoe UI", 10, "bold")

SEVERITY_COLORS = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      GREEN,
}

TYPE_ICONS = {
    "rootkit":         "X",
    "trojan":          "T",
    "spyware":         "S",
    "startup":         "!",
    "suspicious_file": "?",
}


class ThreatKillApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ThreatKill  --  Malware & Rootkit Removal  --  By RAVI CHAUHAN")
        self.geometry("950x720")
        self.minsize(800, 600)
        self.configure(bg=BG)
        self._scanner = ThreatScanner()
        self._scan_result = None
        self._scanning = False
        self._build_ui()
        self._center()

    def _center(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        tk.Frame(self, height=3, bg=ACCENT).pack(fill="x")

        header = tk.Frame(self, bg="#0d0f15", padx=24, pady=16)
        header.pack(fill="x")

        tk.Label(header, text="THREATKILL",
                 font=FONT_TITLE, bg="#0d0f15", fg=TEXT).pack(side="left")
        tk.Label(header, text="   Malware & Rootkit Removal  |  By RAVI CHAUHAN",
                 font=("Segoe UI", 9), bg="#0d0f15", fg=MUTED).pack(side="left", pady=(8,0))
        tk.Label(header, text=f"Windows {platform.release()}",
                 font=("Courier New", 9), bg="#0d0f15", fg=MUTED).pack(side="right")

        # Online status indicator
        self.online_label = tk.Label(header, text="Checking...",
                 font=("Courier New", 9), bg="#0d0f15", fg=MUTED)
        self.online_label.pack(side="right", padx=(0,16))
        self.after(500, self._check_online_status)

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # ── Stats bar ─────────────────────────────────────────────────────────
        stats_frame = tk.Frame(self, bg=SURFACE)
        stats_frame.pack(fill="x")

        self.stat_vars = {}
        stats = [
            ("THREATS",   "0",        RED),
            ("CRITICAL",  "0",        RED),
            ("HIGH",      "0",        ORANGE),
            ("PROCESSES", "--",       ACCENT),
            ("FILES",     "--",       ACCENT),
            ("STATUS",    "IDLE",     MUTED),
        ]
        for i, (label, val, color) in enumerate(stats):
            cell = tk.Frame(stats_frame, bg=SURFACE, padx=18, pady=10)
            cell.pack(side="left", expand=True, fill="x")
            v = tk.StringVar(value=val)
            self.stat_vars[label] = v
            tk.Label(cell, text=label, font=("Courier New", 8),
                     bg=SURFACE, fg=MUTED).pack()
            tk.Label(cell, textvariable=v, font=("Courier New", 15, "bold"),
                     bg=SURFACE, fg=color).pack()
            if i < len(stats) - 1:
                tk.Frame(stats_frame, width=1, bg=BORDER).pack(side="left", fill="y")

        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # ── Progress bar (simple) ─────────────────────────────────────────────
        self.prog_frame = tk.Frame(self, height=4, bg=BORDER)
        self.prog_frame.pack(fill="x")
        self.prog_bar = tk.Frame(self.prog_frame, height=4, bg=BORDER)
        self.prog_bar.pack(fill="x")
        self._prog_animating = False
        self._prog_pos = 0

        # ── Bottom toolbar (packed BEFORE notebook so it always shows) ────────
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", side="bottom")
        toolbar = tk.Frame(self, bg=SURFACE, padx=20, pady=10)
        toolbar.pack(fill="x", side="bottom")

        self.scan_btn = tk.Button(
            toolbar,
            text="  START SCAN  ",
            font=("Courier New", 11, "bold"),
            bg=ACCENT, fg=BG,
            relief="flat", padx=20, pady=8,
            cursor="hand2",
            command=self._start_scan,
            activebackground="#00b8cc",
            activeforeground=BG,
        )
        self.scan_btn.pack(side="left")

        self.remove_all_btn = tk.Button(
            toolbar,
            text="  REMOVE ALL  ",
            font=("Courier New", 11, "bold"),
            bg=RED, fg="white",
            relief="flat", padx=20, pady=8,
            cursor="hand2",
            command=self._remove_all,
            activebackground="#cc0020",
            activeforeground="white",
            state="disabled",
        )
        self.remove_all_btn.pack(side="left", padx=(10, 0))

        self.status_label = tk.Label(
            toolbar,
            text="Ready  --  Click START SCAN to begin",
            font=("Segoe UI", 9),
            bg=SURFACE, fg=MUTED,
        )
        self.status_label.pack(side="right")

        # ── Notebook tabs ─────────────────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("default")
        style.configure("T.TNotebook", background=BG, borderwidth=0)
        style.configure("T.TNotebook.Tab",
                        background=SURFACE, foreground=MUTED,
                        padding=[16, 8], font=("Segoe UI", 10), borderwidth=0)
        style.map("T.TNotebook.Tab",
                  background=[("selected", SURFACE2)],
                  foreground=[("selected", TEXT)])

        self.notebook = ttk.Notebook(self, style="T.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        # Tab 1 - Threats
        self.threat_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.threat_tab, text="   Threats   ")

        # Tab 2 - Scan Log
        self.log_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.log_tab, text="   Scan Log   ")

        # Tab 3 - About
        self.about_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.about_tab, text="   About   ")

        self._build_threat_tab()
        self._build_log_tab()
        self._build_about_tab()

    def _check_online_status(self):
        """Check internet and update the online status badge in header."""
        def _check():
            try:
                import socket
                socket.setdefaulttimeout(4)
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
                online = True
            except Exception:
                online = False

            def _update():
                if online:
                    self.online_label.config(
                        text="  ONLINE — Threat Intel Active  ",
                        fg=BG, bg=GREEN,
                        font=("Courier New", 8, "bold"),
                        padx=6, pady=2,
                    )
                else:
                    self.online_label.config(
                        text="  OFFLINE — Local Scan Only  ",
                        fg=BG, bg=MUTED,
                        font=("Courier New", 8, "bold"),
                        padx=6, pady=2,
                    )
            self.after(0, _update)

        import threading
        threading.Thread(target=_check, daemon=True).start()

    def _build_threat_tab(self):
        container = tk.Frame(self.threat_tab, bg=BG)
        container.pack(fill="both", expand=True)

        self.threat_canvas = tk.Canvas(container, bg=BG, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical",
                                 command=self.threat_canvas.yview)
        self.threat_scroll_frame = tk.Frame(self.threat_canvas, bg=BG)

        self.threat_scroll_frame.bind(
            "<Configure>",
            lambda e: self.threat_canvas.configure(
                scrollregion=self.threat_canvas.bbox("all")))

        self.threat_canvas.create_window((0, 0), window=self.threat_scroll_frame, anchor="nw")
        self.threat_canvas.configure(yscrollcommand=scrollbar.set)
        self.threat_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.threat_canvas.bind_all(
            "<MouseWheel>",
            lambda e: self.threat_canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        # Empty state label
        self.empty_label = tk.Label(
            self.threat_scroll_frame,
            text="\n\nNo threats detected yet\n\nClick  START SCAN  to check your system",
            font=("Segoe UI", 12),
            bg=BG, fg=MUTED, justify="center",
        )
        self.empty_label.pack(pady=60)

    def _build_log_tab(self):
        self.log_text = scrolledtext.ScrolledText(
            self.log_tab,
            font=("Courier New", 10),
            bg="#080a0e", fg=ACCENT,
            insertbackground=ACCENT,
            relief="flat", padx=16, pady=16,
            wrap="word", state="disabled",
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("threat", foreground=RED)
        self.log_text.tag_config("warn",   foreground=YELLOW)
        self.log_text.tag_config("ok",     foreground=GREEN)
        self.log_text.tag_config("header", foreground=ACCENT)
        self.log_text.tag_config("muted",  foreground=MUTED)

    def _build_about_tab(self):
        f = tk.Frame(self.about_tab, bg=BG, padx=40, pady=30)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="THREATKILL", font=("Courier New", 24, "bold"),
                 bg=BG, fg=ACCENT).pack(anchor="w")
        tk.Label(f, text="Malware & Rootkit Removal Tool",
                 font=("Segoe UI", 11), bg=BG, fg=MUTED).pack(anchor="w", pady=(2, 20))

        info = [
            ("Author",   "RAVI CHAUHAN"),
            ("GitHub",   "github.com/Ravirazchauhan"),
            ("Platform", "Windows & Linux"),
            ("Version",  "1.0.0"),
            ("Language", "Python 3.9+"),
        ]
        for label, val in info:
            row = tk.Frame(f, bg=BG, pady=3)
            row.pack(anchor="w", fill="x")
            tk.Label(row, text=f"{label}:", font=("Courier New", 10),
                     bg=BG, fg=MUTED, width=12, anchor="w").pack(side="left")
            tk.Label(row, text=val, font=("Courier New", 10, "bold"),
                     bg=BG, fg=TEXT).pack(side="left")

        tk.Frame(f, height=1, bg=BORDER).pack(fill="x", pady=20)
        tk.Label(f, text="What ThreatKill detects:",
                 font=("Segoe UI", 10, "bold"), bg=BG, fg=TEXT).pack(anchor="w")

        caps = [
            "  Rootkits  --  hidden processes & suspicious kernel modules",
            "  Trojans / RATs  --  30+ known malware process signatures",
            "  Spyware / Keyloggers  --  process & file name matching",
            "  Startup entries  --  registry (Windows) & init scripts (Linux)",
            "  MD5 hash matching  --  known malware file database",
            "  Suspicious directories  --  Temp, AppData, /tmp scanning",
        ]
        for cap in caps:
            tk.Label(f, text=cap, font=("Segoe UI", 10),
                     bg=BG, fg=MUTED, anchor="w").pack(anchor="w", pady=2)

        tk.Frame(f, height=1, bg=BORDER).pack(fill="x", pady=16)
        tk.Label(f,
                 text="For authorised use only. Run as Administrator for full scan coverage.",
                 font=("Segoe UI", 9), bg=BG, fg=ORANGE).pack(anchor="w")

    # ── Progress animation ────────────────────────────────────────────────────

    def _start_progress(self):
        self._prog_animating = True
        self._prog_pos = 0
        self._animate_progress()

    def _animate_progress(self):
        if not self._prog_animating:
            return
        self.prog_bar.configure(bg=ACCENT)
        self._prog_pos += 1
        if self._prog_pos % 2 == 0:
            self.prog_bar.configure(bg=BORDER)
        self.after(300, self._animate_progress)

    def _stop_progress(self):
        self._prog_animating = False
        self.prog_bar.configure(bg=GREEN)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg):
        def _append():
            self.log_text.config(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            tag = "muted"
            if any(w in msg for w in ["THREAT", "MALWARE", "ROOTKIT"]):
                tag = "threat"
            elif any(w in msg for w in ["WARNING", "SUSPICIOUS", "STARTUP"]):
                tag = "warn"
            elif any(w in msg for w in ["complete", "OK", "Done"]):
                tag = "ok"
            elif msg.startswith("---") or "ThreatKill" in msg:
                tag = "header"
            self.log_text.insert("end", f"[{ts}] {msg}\n", tag)
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        self.after(0, _append)

    def _set_stat(self, **kwargs):
        def _upd():
            for k, v in kwargs.items():
                if k in self.stat_vars:
                    self.stat_vars[k].set(str(v))
        self.after(0, _upd)

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True

        # Clear previous results
        for w in self.threat_scroll_frame.winfo_children():
            w.destroy()
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

        self.scan_btn.config(text="  SCANNING...  ", state="disabled", bg=MUTED)
        self.remove_all_btn.config(state="disabled")
        self.status_label.config(text="Scanning your system...", fg=ACCENT)
        self._start_progress()
        self._set_stat(STATUS="SCANNING", THREATS="...", CRITICAL="...",
                       HIGH="...", PROCESSES="...", FILES="...")

        self.notebook.select(1)  # Switch to Scan Log tab

        scanner = ThreatScanner()
        scanner.run_full_scan(
            log_callback=self._log,
            done_callback=self._scan_done,
            quick=True,
        )

    def _scan_done(self, result):
        self._scan_result = result
        self._scanning = False

        def _update():
            self._stop_progress()
            self.scan_btn.config(text="  SCAN AGAIN  ", state="normal", bg=ACCENT)
            self.status_label.config(
                text=f"Scan complete  --  {len(result.threats)} threat(s) found  --  {result.duration:.1f}s",
                fg=GREEN if result.is_clean else RED,
            )
            self._set_stat(
                THREATS=len(result.threats),
                CRITICAL=result.critical_count,
                HIGH=result.high_count,
                PROCESSES=result.scanned_processes,
                FILES=result.scanned_files,
                STATUS="CLEAN" if result.is_clean else "THREATS!",
            )

            # Clear threat panel
            for w in self.threat_scroll_frame.winfo_children():
                w.destroy()

            if result.is_clean:
                tk.Label(
                    self.threat_scroll_frame,
                    text="\n\nSystem is Clean!\n\nNo threats were detected on your system.",
                    font=("Segoe UI", 13),
                    bg=BG, fg=GREEN, justify="center",
                ).pack(pady=60)
            else:
                tk.Label(
                    self.threat_scroll_frame,
                    text=f"  {len(result.threats)} Threat(s) Detected:",
                    font=("Segoe UI", 11, "bold"),
                    bg=BG, fg=RED, anchor="w",
                ).pack(fill="x", padx=16, pady=(14, 6))

                order = ["critical", "high", "medium", "low", "info"]
                sorted_threats = sorted(
                    result.threats,
                    key=lambda t: order.index(t.severity) if t.severity in order else 5
                )

                for threat in sorted_threats:
                    self._make_threat_row(threat)

                self.remove_all_btn.config(state="normal")

            self.notebook.select(0)  # Switch to Threats tab

        self.after(0, _update)

    def _make_threat_row(self, threat):
        sev_color = SEVERITY_COLORS.get(threat.severity, MUTED)

        row = tk.Frame(self.threat_scroll_frame, bg=SURFACE2, pady=0)
        row.pack(fill="x", padx=14, pady=4)

        # Colour strip on left
        tk.Frame(row, width=5, bg=sev_color).pack(side="left", fill="y")

        body = tk.Frame(row, bg=SURFACE2, padx=12, pady=10)
        body.pack(side="left", fill="x", expand=True)

        # Title row
        title_row = tk.Frame(body, bg=SURFACE2)
        title_row.pack(fill="x")

        tk.Label(title_row,
                 text=f"[{threat.severity.upper()}]",
                 font=("Courier New", 9, "bold"),
                 bg=sev_color, fg=BG, padx=6, pady=2).pack(side="left")

        tk.Label(title_row,
                 text=f"  {threat.name}",
                 font=FONT_HEAD, bg=SURFACE2, fg=TEXT).pack(side="left")

        tk.Label(title_row,
                 text=f"  [{threat.threat_type.upper()}]",
                 font=("Courier New", 8),
                 bg=SURFACE2, fg=MUTED).pack(side="left")

        # Description
        tk.Label(body, text=threat.description,
                 font=("Segoe UI", 9), bg=SURFACE2, fg=MUTED,
                 anchor="w", wraplength=540, justify="left").pack(fill="x", pady=(5, 2))

        # Location
        tk.Label(body, text=f"Location: {threat.location[:90]}",
                 font=("Courier New", 8), bg=SURFACE2, fg="#2a3050",
                 anchor="w").pack(fill="x")

        # Remove button
        btn_area = tk.Frame(row, bg=SURFACE2, padx=10)
        btn_area.pack(side="right", fill="y")

        if threat.removable and not threat.removed:
            def make_remove(t, r):
                def do_remove():
                    if messagebox.askyesno("Remove Threat",
                        f"Remove this threat?\n\n{t.name}\n\n{t.location}"):
                        success = remove_threat(t, self._log)
                        if success:
                            r.configure(text="REMOVED", bg=GREEN, fg=BG, state="disabled")
                        else:
                            messagebox.showerror("Error",
                                "Could not remove automatically.\nTry running as Administrator.")
                return do_remove

            remove_btn = tk.Button(
                btn_area,
                text="REMOVE",
                font=("Courier New", 9, "bold"),
                bg=RED, fg="white",
                relief="flat", padx=10, pady=4,
                cursor="hand2",
                activebackground="#cc0020",
            )
            remove_btn.config(command=make_remove(threat, remove_btn))
            remove_btn.pack(side="right", pady=12)
        else:
            label = "REMOVED" if threat.removed else "MANUAL FIX"
            color = GREEN if threat.removed else MUTED
            tk.Label(btn_area, text=label,
                     font=("Courier New", 9, "bold"),
                     bg=SURFACE2, fg=color).pack(side="right", pady=12)

        tk.Frame(row, height=1, bg=BORDER).pack(side="bottom", fill="x")

    def _remove_all(self):
        if not self._scan_result:
            return
        removable = [t for t in self._scan_result.threats
                     if t.removable and not t.removed]
        if not removable:
            messagebox.showinfo("Nothing to remove",
                                "All removable threats have already been removed.")
            return
        if not messagebox.askyesno("Remove All",
            f"Remove {len(removable)} threat(s)?\n\nThis cannot be undone.",
            icon="warning"):
            return
        removed = 0
        for t in removable:
            if remove_threat(t, self._log):
                removed += 1
        messagebox.showinfo("Done",
            f"Removed {removed} of {len(removable)} threats.\n"
            "Some may need manual removal or Administrator rights.")
        self._scan_done(self._scan_result)


def main():
    app = ThreatKillApp()
    app.mainloop()


if __name__ == "__main__":
    main()
