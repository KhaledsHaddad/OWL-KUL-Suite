import tkinter as tk
from tkinter import scrolledtext, ttk
import subprocess
import threading

BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
FONT = ("Consolas", 12, "bold")
BTN_WIDTH = 20
BTN_HEIGHT = 2

def confirm_and_run(description, command):
    target = target_entry.get().strip()
    if not target:
        return
    full_cmd = f"nmap {command} {target}"
    
    confirm_win = tk.Toplevel(root)
    confirm_win.title("Confirm Scan")
    confirm_win.configure(bg=BG_COLOR)
    
    tk.Label(confirm_win, text="Scan Description:", fg=FG_COLOR, bg=BG_COLOR, font=("Consolas", 12, "bold")).pack(pady=(10,0))
    desc_box = scrolledtext.ScrolledText(confirm_win, width=70, height=15, fg=FG_COLOR, bg=BG_COLOR, font=("Consolas", 11), insertbackground=FG_COLOR)
    desc_box.pack(padx=10, pady=10)
    desc_box.insert(tk.END, f"{description}\n\nFull command:\n{full_cmd}\n\nDo you want to proceed?")
    desc_box.config(state=tk.DISABLED)
    
    btn_frame = tk.Frame(confirm_win, bg=BG_COLOR)
    btn_frame.pack(pady=(0,10))
    
    tk.Button(btn_frame, text="Run Scan", command=lambda:[run_nmap(full_cmd), confirm_win.destroy()],
              fg=FG_COLOR, bg=BG_COLOR, font=FONT, width=15, height=2, relief="ridge", bd=3).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Cancel", command=confirm_win.destroy,
              fg=FG_COLOR, bg=BG_COLOR, font=FONT, width=15, height=2, relief="ridge", bd=3).pack(side=tk.LEFT, padx=5)

def run_nmap(full_command):
    results_box.delete(1.0, tk.END)
    thread = threading.Thread(target=execute_nmap, args=(full_command,))
    thread.start()

def execute_nmap(full_command):
    try:
        process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        for line in process.stdout:
            results_box.insert(tk.END, line)
            results_box.see(tk.END)
    except Exception as e:
        results_box.insert(tk.END, f"Error: {e}\n")

root = tk.Tk()
root.title("Nmap GUI Tool - khaled.s.haddad | khaledhaddad.tech")
root.configure(bg=BG_COLOR)

header = tk.Label(root, text="Nmap Advanced", fg=FG_COLOR, bg=BG_COLOR, font=("Consolas", 16, "bold"))
header.pack(pady=(10,5))
sub_header = tk.Label(root, text="by khaled.s.haddad | khaledhaddad.tech", fg=FG_COLOR, bg=BG_COLOR, font=("Consolas", 11))
sub_header.pack(pady=(0,10))

frame_top = tk.Frame(root, bg=BG_COLOR)
frame_top.pack(pady=5)
tk.Label(frame_top, text="Target:", fg=FG_COLOR, bg=BG_COLOR, font=FONT).pack(side=tk.LEFT)
target_entry = tk.Entry(frame_top, font=FONT, fg=FG_COLOR, bg=BG_COLOR, insertbackground=FG_COLOR, width=30)
target_entry.pack(side=tk.LEFT, padx=5)

notebook = ttk.Notebook(root)
notebook.pack(pady=5, expand=True, fill='both')

style = ttk.Style()
style.theme_use("default")
style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
style.configure("TNotebook.Tab", background=BG_COLOR, foreground=FG_COLOR, font=FONT)
style.map("TNotebook.Tab", background=[("selected", FG_COLOR)], foreground=[("selected", BG_COLOR)])

frames = {}
for tab_name in ["Basic Scans", "Advanced Scans", "Scripts", "Special"]:
    frame = tk.Frame(notebook, bg=BG_COLOR)
    notebook.add(frame, text=tab_name)
    frames[tab_name] = frame

buttons_basic = [
    ("Ping Scan", "-sn", "Sends ICMP echo requests to check if the target is alive. Useful for quickly identifying live hosts."),
    ("Quick Scan", "-T4 -F", "Performs a fast scan on common ports. Ideal for quick reconnaissance."),
    ("Full Scan", "-p-", "Scans all 65535 TCP ports. Takes longer but finds all open ports."),
    ("Service Version", "-sV", "Detects versions of running services. Helps identify software and potential vulnerabilities."),
    ("OS Detection", "-O", "Attempts to determine the target's operating system based on TCP/IP stack fingerprinting.")
]

buttons_advanced = [
    ("Vuln Scan", "--script vuln", "Runs vulnerability detection scripts included in Nmap. Useful for finding known security issues."),
    ("Aggressive Scan", "-A", "Performs OS detection, version detection, script scanning, and traceroute in one command."),
    ("TCP Connect Scan", "-sT", "Performs a full TCP connect scan. Useful if SYN scan is blocked."),
    ("SYN Scan", "-sS", "Performs a stealth SYN scan to detect open ports without completing TCP handshake."),
    ("UDP Scan", "-sU", "Scans UDP ports. Slower but important to detect UDP services."),
    ("Top Ports Scan", "--top-ports 20", "Scans the 20 most common ports. Fast overview of active services."),
    ("Traceroute", "--traceroute", "Maps the route packets take to reach the target. Useful for network mapping."),
    ("Firewall Evasion", "-f", "Uses packet fragmentation to bypass some simple firewall rules. Be cautious with usage.")
]

buttons_scripts = [
    ("Default Scripts", "--script default", "Runs Nmap's default set of scripts for general scanning."),
    ("Exploit Scripts", "--script exploit", "Runs scripts that attempt to exploit known vulnerabilities."),
    ("Safe Scripts", "--script safe", "Runs only scripts considered safe for scanning without affecting the target."),
    ("Malware Scripts", "--script malware", "Runs malware detection scripts included in NSE."),
    ("Auth Scripts", "--script auth", "Tests authentication mechanisms and checks for weak credentials."),
    ("Brute Scripts", "--script brute", "Performs brute force attacks using NSE scripts (use with caution)."),
    ("Discovery Scripts", "--script discovery", "Runs scripts that help discover additional hosts and services.")
]

buttons_special = [
    ("Intense Scan", "-T4 -A -v", "Performs intense scanning with verbose output, including OS and service detection, script scanning, and traceroute."),
    ("Scan with OS & Services", "-O -sV", "Combines OS detection and service version detection in one command."),
    ("IPv6 Scan", "-6", "Scans targets over IPv6 addresses."),
    ("Timing T0 Scan", "-T0", "Paranoid scan: extremely slow to avoid detection by IDS."),
    ("Timing T5 Scan", "-T5", "Insane scan: very fast but may trigger defenses."),
    ("Custom Ports Scan", "-p 21,22,80,443", "Scan specific ports defined by the user."),
    ("Full NSE Scan", "-sC", "Runs the default NSE scripts on all detected ports for comprehensive scanning.")
]

def create_buttons(frame, buttons):
    for i, (text, cmd, desc) in enumerate(buttons):
        r = i // 2
        c = i % 2
        tk.Button(frame, text=text, command=lambda d=desc, c=cmd: confirm_and_run(d, c),
                  fg=FG_COLOR, bg=BG_COLOR, font=FONT, width=BTN_WIDTH, height=BTN_HEIGHT, relief="ridge", bd=2).grid(row=r, column=c, padx=6, pady=6)

create_buttons(frames["Basic Scans"], buttons_basic)
create_buttons(frames["Advanced Scans"], buttons_advanced)
create_buttons(frames["Scripts"], buttons_scripts)
create_buttons(frames["Special"], buttons_special)

results_box = scrolledtext.ScrolledText(root, width=110, height=25, fg=FG_COLOR, bg=BG_COLOR, font=("Consolas", 11), insertbackground=FG_COLOR)
results_box.pack(pady=10, expand=True, fill='both')

footer = tk.Label(root, text="© khaled.s.haddad | khaledhaddad.tech", fg=FG_COLOR, bg=BG_COLOR, font=("Consolas", 11))
footer.pack(side=tk.BOTTOM, pady=5)

root.mainloop()
