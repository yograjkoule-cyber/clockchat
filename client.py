"""
Desktop chat app written in Python (Tkinter).

1. Start the server first:   python server.py
2. Then start this app:      python client.py
   (run it twice, in two terminals, to chat between two accounts on one PC)

To also enable voice messages, additionally install:
    pip install sounddevice numpy
If these aren't installed, the microphone button is simply hidden and
everything else still works.
"""
import base64
import json
import math
import os
import queue
import re
import tempfile
import threading
import time
import traceback
import wave
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

import requests
import websocket  # from the "websocket-client" package

import chatcrypto as cc

try:
    import sounddevice as sd
    import numpy as np
    VOICE_AVAILABLE = True
except Exception:
    VOICE_AVAILABLE = False  # the mic button is hidden if "sounddevice" isn't installed

APP_NAME = "MyChat"  # <- change this to your app name
SERVER = os.environ.get("CHAT_SERVER", "http://localhost:5000")  # <- address of your server

GREEN, DARK, LIGHT = "#00a884", "#075e54", "#25d366"
FONT = "Segoe UI"
FILE_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB; the server enforces the same limit
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received_files")
VOICE_SAMPLE_RATE = 16000  # 16 kHz mono is plenty for speech and keeps files small


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class ClockLogo(tk.Canvas):
    """The app logo: a clock that shows the real time."""

    def __init__(self, parent, size=90, bg="white"):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0)
        self.size = size
        self.tick()

    def tick(self):
        if not self.winfo_exists():
            return
        s, c = self.size, self.size / 2
        self.delete("all")
        self.create_oval(2, 2, s - 2, s - 2, fill=GREEN, outline=GREEN)
        self.create_oval(s * 0.1, s * 0.1, s * 0.9, s * 0.9, fill="white", outline="white")
        for k in range(12):
            a = math.radians(k * 30)
            r1, r2 = c * 0.72, c * 0.82
            self.create_line(c + r1 * math.sin(a), c - r1 * math.cos(a),
                             c + r2 * math.sin(a), c - r2 * math.cos(a), fill=GREEN, width=2)
        t = time.localtime()
        hands = [((t.tm_hour % 12 + t.tm_min / 60) * 30, 0.45, 4, DARK),
                 (t.tm_min * 6, 0.65, 3, DARK),
                 (t.tm_sec * 6, 0.72, 1, LIGHT)]
        for deg, length, width, color in hands:
            a = math.radians(deg)
            self.create_line(c, c, c + c * length * math.sin(a), c - c * length * math.cos(a),
                             fill=color, width=width, capstyle="round")
        self.create_oval(c - 3, c - 3, c + 3, c + 3, fill=DARK, outline=DARK)
        self.after(1000, self.tick)


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry("900x620")
        root.minsize(720, 460)
        self.q = queue.Queue()  # messages from background threads to the screen
        self.reset_state()
        self.build_login()

    def reset_state(self):
        self.mode = "login"
        self.token = self.me = self.priv = self.my_pub = self.ws = self.peer = None
        self.users, self.online, self.rows, self.unread, self.keys = {}, set(), [], {}, {}
        self.groups, self.group_keys, self.group_raw_keys = {}, {}, {}  # gid -> info, gid -> AESGCM, gid -> raw bytes
        self.files = {}  # transfer_id -> info dict, for files sent/received
        self.recording = None
        self.base_sub, self.last_typing = "", 0

    # ------------------------------------------------------------ server calls
    def api(self, method, path, body=None):
        headers = {"Authorization": "Bearer " + self.token} if self.token else {}
        try:
            r = requests.request(method, SERVER + path, json=body, headers=headers, timeout=10)
        except requests.RequestException:
            raise RuntimeError("Cannot reach the server. Is server.py running?")
        try:
            data = r.json()
        except ValueError:
            data = {}
        if not r.ok:
            raise RuntimeError(data.get("error", "Request failed"))
        return data

    # ------------------------------------------------------------ login screen
    def build_login(self):
        self.root.configure(bg="#d1d7db")
        card = tk.Frame(self.root, bg="white", padx=36, pady=28)
        card.place(relx=0.5, rely=0.5, anchor="center")
        self.login_frame = card
        ClockLogo(card, 90).pack()
        tk.Label(card, text=APP_NAME, font=(FONT, 20, "bold"), fg=GREEN, bg="white").pack(pady=(6, 0))
        tk.Label(card, text="Private. End-to-end encrypted.", fg="#667781", bg="white").pack(pady=(0, 12))
        self.u = tk.Entry(card, width=30, font=(FONT, 11))
        self.u.pack(pady=4, ipady=5)
        self.p = tk.Entry(card, width=30, show="*", font=(FONT, 11))
        self.p.pack(pady=4, ipady=5)
        tk.Label(card, text="Username: a-z, 0-9, _ (3-20)   Password: 10+ characters",
                 fg="#8696a0", bg="white", font=(FONT, 8)).pack()
        self.go_btn = tk.Button(card, text="Log in", command=self.submit, bg=GREEN, fg="white",
                                relief="flat", padx=20, pady=6, font=(FONT, 11, "bold"))
        self.go_btn.pack(pady=(12, 4))
        self.msg = tk.Label(card, text="", fg="#c0392b", bg="white", wraplength=280)
        self.msg.pack()
        self.switch_btn = tk.Label(card, text="New here? Create an account", fg=GREEN, bg="white", cursor="hand2")
        self.switch_btn.pack(pady=(6, 0))
        self.switch_btn.bind("<Button-1>", lambda e: self.toggle_mode())
        self.p.bind("<Return>", lambda e: self.submit())
        self.u.focus()

    def say(self, text, color="#c0392b"):
        self.msg.config(text=text, fg=color)

    def toggle_mode(self):
        self.mode = "register" if self.mode == "login" else "login"
        login = self.mode == "login"
        self.go_btn.config(text="Log in" if login else "Create account")
        self.switch_btn.config(text="New here? Create an account" if login else "Already have an account? Log in")
        self.say("")

    def submit(self):
        username, password = self.u.get().strip().lower(), self.p.get()
        if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
            return self.say("Username: 3-20 letters, numbers or _")
        if len(password) < 10:
            return self.say("Password must be at least 10 characters")
        self.say("Please wait...", "#667781")
        self.go_btn.config(state="disabled")
        threading.Thread(target=self.auth_worker, args=(username, password), daemon=True).start()

    def auth_worker(self, username, password):
        """Runs in a background thread so the window does not freeze."""
        try:
            wrap_key, auth = cc.derive_secrets(username, password)
            if self.mode == "register":
                priv = cc.new_private_key()
                pub = cc.public_jwk(priv.public_key())
                r = self.api("POST", "/api/register", {
                    "username": username, "auth": auth, "public_key": json.dumps(pub),
                    "wrapped_key": cc.lock_private_key(priv, wrap_key)})
            else:
                r = self.api("POST", "/api/login", {"username": username, "auth": auth})
                try:
                    priv = cc.unlock_private_key(r["wrapped_key"], wrap_key)
                except Exception:
                    raise RuntimeError("Could not unlock your keys")
                pub = json.loads(r["public_key"])
            self.q.put(("authed", username, r["token"], priv, pub))
        except Exception as e:
            self.q.put(("autherr", str(e)))

    # ------------------------------------------------------------ chat screen
    def build_chat(self):
        self.login_frame.destroy()
        self.root.configure(bg="white")
        side = tk.Frame(self.root, width=270, bg="white")
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        top = tk.Frame(side, bg="#f0f2f5")
        top.pack(fill="x")
        ClockLogo(top, 38, bg="#f0f2f5").pack(side="left", padx=8, pady=8)
        tk.Label(top, text=f"{APP_NAME}\n@{self.me}", justify="left", bg="#f0f2f5",
                 font=(FONT, 10, "bold")).pack(side="left")
        tk.Button(top, text="Log out", command=self.logout, relief="flat", bg="#f0f2f5").pack(side="right", padx=8)

        toolbar = tk.Frame(side, bg="white")
        toolbar.pack(fill="x")
        tk.Button(toolbar, text="+ New Group", command=self.open_new_group, relief="flat",
                  bg="white", fg=GREEN).pack(side="left", padx=6, pady=4)
        tk.Button(toolbar, text="Status", command=self.open_status, relief="flat",
                  bg="white", fg=GREEN).pack(side="left", padx=6, pady=4)

        self.listbox = tk.Listbox(side, font=(FONT, 12), activestyle="none", borderwidth=0,
                                  highlightthickness=0, selectbackground="#e9edef", selectforeground="black")
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_pick)

        main = tk.Frame(self.root, bg="#efeae2")
        main.pack(side="left", fill="both", expand=True)
        head = tk.Frame(main, bg="#f0f2f5")
        head.pack(fill="x")
        head_top = tk.Frame(head, bg="#f0f2f5")
        head_top.pack(fill="x", padx=12, pady=(8, 0))
        self.peer_label = tk.Label(head_top, text="Select a chat", font=(FONT, 12, "bold"), bg="#f0f2f5", anchor="w")
        self.peer_label.pack(side="left", fill="x", expand=True)
        self.manage_btn = tk.Button(head_top, text="\u2699 Manage", command=self.open_group_manage,
                                    relief="flat", bg="#f0f2f5", fg=GREEN)
        self.sub = tk.Label(head, text="", font=(FONT, 9), fg="#667781", bg="#f0f2f5", anchor="w")
        self.sub.pack(fill="x", padx=12, pady=(0, 8))

        bar = tk.Frame(main, bg="#f0f2f5")
        bar.pack(side="bottom", fill="x")
        tk.Button(bar, text="\U0001F4CE", command=self.attach_file, relief="flat",
                  bg="#f0f2f5", font=(FONT, 12)).pack(side="left", padx=(10, 0), pady=10)
        if VOICE_AVAILABLE:
            self.mic_btn = tk.Button(bar, text="\U0001F3A4", command=self.toggle_recording, relief="flat",
                                     bg="#f0f2f5", font=(FONT, 12))
            self.mic_btn.pack(side="left", pady=10)
        self.entry = tk.Entry(bar, font=(FONT, 12))
        self.entry.pack(side="left", fill="x", expand=True, padx=10, pady=10, ipady=6)
        tk.Button(bar, text="Send", command=self.send, bg=GREEN, fg="white", relief="flat",
                  padx=16, pady=4).pack(side="right", padx=10)
        self.entry.bind("<Return>", lambda e: self.send())
        self.entry.bind("<Key>", self.on_key)

        self.text = tk.Text(main, state="disabled", wrap="word", bg="#efeae2", borderwidth=0,
                            highlightthickness=0, font=(FONT, 11), padx=10, pady=8)
        self.text.pack(fill="both", expand=True)
        self.text.tag_configure("me", justify="right", background="#d9fdd3", rmargin=12, spacing1=8)
        self.text.tag_configure("them", justify="left", background="#ffffff", lmargin1=12, lmargin2=12, spacing1=8)
        self.text.tag_configure("time_me", justify="right", foreground="#667781", font=(FONT, 8), rmargin=12)
        self.text.tag_configure("time_them", justify="left", foreground="#667781", font=(FONT, 8), lmargin1=12)

    def load_users_sync(self):
        r = self.api("GET", "/api/users")
        for u in r["users"]:
            self.users[u["username"]] = json.loads(u["public_key"])
        self.online = set(r["online"])
        self.load_groups_sync()  # also refreshes the list

    def load_groups_sync(self):
        r = self.api("GET", "/api/groups")
        self.groups = {g["id"]: g for g in r["groups"]}
        self.refresh_list()

    def group_key_bytes(self, gid):
        if gid not in self.group_raw_keys:
            g = self.groups[gid]
            # the creator's private key was used to lock this key, so their public key unlocks it
            self.group_raw_keys[gid] = cc.unwrap_group_key(g["wrapped_key"], self.priv, self.users[g["creator"]])
        return self.group_raw_keys[gid]

    def group_key(self, gid):
        if gid not in self.group_keys:
            self.group_keys[gid] = cc.group_aead(self.group_key_bytes(gid))
        return self.group_keys[gid]

    def refresh_list(self):
        people = sorted(n for n in self.users if n != self.me)
        groups = sorted(self.groups.values(), key=lambda g: g["name"])
        self.rows = [("group", g["id"]) for g in groups] + [("dm", n) for n in people]
        self.listbox.delete(0, "end")
        for i, row in enumerate(self.rows):
            if row[0] == "group":
                g = self.groups[row[1]]
                badge = f"   ({self.unread.get(row,0)} new)" if self.unread.get(row) else ""
                self.listbox.insert("end", f" \U0001F465  {g['name']}{badge}")
                self.listbox.itemconfig(i, fg="#111111")
            else:
                n = row[1]
                dot = "\u25CF" if n in self.online else "\u25CB"
                badge = f"   ({self.unread.get(row,0)} new)" if self.unread.get(row) else ""
                self.listbox.insert("end", f" {dot}  {n}{badge}")
                self.listbox.itemconfig(i, fg="#111111" if n in self.online else "#8696a0")
        if self.peer in self.rows:
            self.listbox.selection_set(self.rows.index(self.peer))

    def on_pick(self, _event):
        sel = self.listbox.curselection()
        if not sel:
            return
        row = self.rows[sel[0]]
        if row[0] == "dm":
            self.open_dm(row[1])
        else:
            self.open_group(row[1])

    def key_for(self, peer):
        if peer not in self.keys:
            self.keys[peer] = cc.chat_key(self.priv, self.users[peer])
        return self.keys[peer]

    def clear_chat_view(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

    def open_dm(self, name):
        self.peer = ("dm", name)
        self.unread[self.peer] = 0
        self.peer_label.config(text=name)
        self.manage_btn.pack_forget()
        self.clear_chat_view()
        try:
            self.base_sub = "End-to-end encrypted  |  Safety code: " + cc.safety_code(self.my_pub, self.users[name])
            self.sub.config(text=self.base_sub)
            for item in self.api("GET", "/api/history/" + name)["items"]:
                self.show_history_item(self.peer, item)
        except Exception as e:
            self.sub.config(text="Error: " + str(e))
        self.refresh_list()
        self.entry.focus()

    def open_group(self, gid):
        self.peer = ("group", gid)
        self.unread[self.peer] = 0
        g = self.groups[gid]
        self.peer_label.config(text="\U0001F465 " + g["name"])
        if g["creator"] == self.me:
            self.manage_btn.pack(side="right")
        else:
            self.manage_btn.pack_forget()
        self.clear_chat_view()
        try:
            self.group_key(gid)  # unlock now so any error shows up right away
            self.base_sub = "End-to-end encrypted group  |  Members: " + ", ".join(g["members"])
            self.sub.config(text=self.base_sub)
            for item in self.api("GET", f"/api/group/{gid}/history")["items"]:
                self.show_history_item(self.peer, item)
        except Exception as e:
            self.sub.config(text="Error: " + str(e))
        self.refresh_list()
        self.entry.focus()

    def show_history_item(self, row, item):
        if item["msgkind"] == "text":
            self.show_text(row, item)
        else:
            self.files[item["transfer_id"]] = {**item, "row": row, "downloaded_path": None, "downloading": False}
            self.render_file_line(row, item["transfer_id"])

    # ---- plain text messages ----
    def render_text(self, text, mine, ts):
        side = "me" if mine else "them"
        self.text.config(state="normal")
        self.text.insert("end", f" {text} ", side)
        self.text.insert("end", "\n")
        self.text.insert("end", time.strftime("%H:%M", time.localtime(ts)), "time_" + side)
        self.text.insert("end", "\n")
        self.text.config(state="disabled")
        self.text.see("end")

    def show_text(self, row, m):
        what, who = row
        key = self.key_for(who) if what == "dm" else self.group_key(who)
        try:
            text = cc.decrypt(key, m["iv"], m["ct"])
        except Exception:
            text = "(!) Could not decrypt this message"
        self.render_text(text, m["sender"] == self.me, m["ts"])

    def show_dm(self, m):
        self.show_text(("dm", m["receiver"] if m["sender"] == self.me else m["sender"]), m)

    def show_group(self, gid, m):
        self.show_text(("group", gid), m)

    def send(self):
        text = self.entry.get().strip()
        if not text or not self.peer or not self.ws:
            return
        what, who = self.peer
        try:
            if what == "dm":
                iv, ct = cc.encrypt(self.key_for(who), text)
                self.ws.send(json.dumps({"type": "msg", "to": who, "iv": iv, "ct": ct}))
            else:
                iv, ct = cc.encrypt(self.group_key(who), text)
                self.ws.send(json.dumps({"type": "gmsg", "group_id": who, "iv": iv, "ct": ct}))
            self.entry.delete(0, "end")
        except Exception:
            self.sub.config(text="Not connected. Trying to reconnect...")

    # ---- files, sent and received in small encrypted pieces ----
    def render_file_line(self, row, transfer_id):
        info = self.files[transfer_id]
        mine = info["sender"] == self.me
        side = "me" if mine else "them"
        if info.get("category") == "voice":
            icon, kind_word = "\U0001F3A4 Voice message", "play"
        else:
            icon, kind_word = f"\U0001F4CE {info['name']}", "download"
        label = f" {icon}  ({human_size(info['size'])})"
        label += "  \u2014 sent" if mine else f"  \u2014 click to {kind_word}"
        tag = f"file_{transfer_id}"
        self.text.config(state="normal")
        self.text.insert("end", label, (side, tag))
        self.text.insert("end", "\n")
        self.text.insert("end", time.strftime("%H:%M", time.localtime(info["ts"])), "time_" + side)
        self.text.insert("end", "\n")
        self.text.config(state="disabled")
        self.text.see("end")
        if not mine:
            self.text.tag_configure(tag, underline=1)
            self.text.tag_bind(tag, "<Enter>", lambda e: self.text.config(cursor="hand2"))
            self.text.tag_bind(tag, "<Leave>", lambda e: self.text.config(cursor=""))
            self.text.tag_bind(tag, "<Button-1>", lambda e, t=transfer_id: self.on_file_click(t))

    def append_note(self, row, text):
        if row == self.peer:
            self.text.config(state="normal")
            self.text.insert("end", f" {text} \n", "them")
            self.text.config(state="disabled")
            self.text.see("end")

    def attach_file(self):
        if not self.peer:
            return messagebox.showinfo(APP_NAME, "Open a chat first.")
        path = filedialog.askopenfilename(title="Choose a file to send")
        if not path:
            return
        try:
            size = os.path.getsize(path)
        except OSError as e:
            return messagebox.showerror(APP_NAME, f"Could not read that file: {e}")
        if size > FILE_MAX_BYTES:
            return messagebox.showerror(APP_NAME, "That file is over the 4 GB limit.")
        self.start_sending(path, os.path.basename(path), size, "file")

    def toggle_recording(self):
        if self.recording is not None:
            self.stop_recording()
            return
        if not self.peer:
            return messagebox.showinfo(APP_NAME, "Open a chat first.")
        frames = []

        def callback(indata, frame_count, time_info, status):
            frames.append(indata.copy())

        try:
            stream = sd.InputStream(samplerate=VOICE_SAMPLE_RATE, channels=1, dtype="int16", callback=callback)
            stream.start()
        except Exception as e:
            return messagebox.showerror(APP_NAME, f"Could not access the microphone: {e}")
        self.recording = {"stream": stream, "frames": frames, "row": self.peer, "started": time.time()}
        self.mic_btn.config(text="\u23F9", fg="#c0392b")

    def stop_recording(self):
        rec, self.recording = self.recording, None
        self.mic_btn.config(text="\U0001F3A4", fg="black")
        try:
            rec["stream"].stop()
            rec["stream"].close()
        except Exception:
            pass
        duration = time.time() - rec["started"]
        if duration < 0.4 or not rec["frames"]:
            return  # too short to be a real message; quietly drop it
        audio = np.concatenate(rec["frames"], axis=0)
        path = os.path.join(tempfile.gettempdir(), f"voice_{int(time.time())}.wav")
        with wave.open(path, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)  # 16-bit samples
            wf.setframerate(VOICE_SAMPLE_RATE)
            wf.writeframes(audio.tobytes())
        size = os.path.getsize(path)
        mins, secs = divmod(int(duration), 60)
        name = f"Voice message ({mins}:{secs:02d}).wav"
        self.start_sending(path, name, size, "voice", row=rec["row"])

    def start_sending(self, path, name, size, category, row=None):
        """Registers a transfer with the server, then uploads the file in the background."""
        row = row or self.peer
        try:
            what, who = row
            body = {"kind": what, "name": name, "size": size, "category": category}
            body["to" if what == "dm" else "group_id"] = who
            r = self.api("POST", "/api/files", body)
        except Exception as e:
            return messagebox.showerror(APP_NAME, f"Could not start sending: {e}")
        key = self.key_for(who) if what == "dm" else self.group_key(who)
        threading.Thread(
            target=self.upload_worker,
            args=(row, path, r["transfer_id"], r["chunk_size"], r["total_chunks"], key, name, size, category),
            daemon=True,
        ).start()

    def upload_worker(self, row, path, transfer_id, chunk_size, total_chunks, key, name, size, category):
        """Runs in a background thread: reads, encrypts and uploads the file piece by piece."""
        try:
            with open(path, "rb") as f:
                for idx in range(total_chunks):
                    piece = f.read(chunk_size)
                    b64 = base64.b64encode(piece).decode()
                    iv, ct = cc.encrypt(key, b64)
                    self.api("POST", f"/api/files/{transfer_id}/chunk/{idx}", {"iv": iv, "ct": ct})
            self.q.put(("upload_done", row, transfer_id, name, size, category))
        except Exception as e:
            self.q.put(("upload_error", row, name, str(e)))

    def fetch_file_meta(self, transfer_id):
        try:
            meta = self.api("GET", f"/api/files/{transfer_id}")
            self.q.put(("file_meta", transfer_id, meta))
        except Exception:
            pass  # the file will still show up next time this chat's history is loaded

    def make_download_path(self, name):
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9 ._-]", "_", name)[:120] or "file"
        path = os.path.join(DOWNLOAD_DIR, safe)
        base, ext = os.path.splitext(path)
        n = 1
        while os.path.exists(path):
            path = f"{base} ({n}){ext}"
            n += 1
        return path

    def on_file_click(self, transfer_id):
        info = self.files.get(transfer_id)
        if not info:
            return
        if info["downloaded_path"]:
            return messagebox.showinfo(APP_NAME, f"Already saved to:\n{info['downloaded_path']}")
        if info["downloading"]:
            return messagebox.showinfo(APP_NAME, "Already downloading...")
        info["downloading"] = True
        what, who = info["row"]
        # a file is only clickable when someone else sent it, so info["sender"] is always the other party
        key = self.key_for(info["sender"]) if what == "dm" else self.group_key(who)
        dest = self.make_download_path(info["name"])
        threading.Thread(
            target=self.download_worker,
            args=(transfer_id, dest, info["total_chunks"], key),
            daemon=True,
        ).start()

    def download_worker(self, transfer_id, dest, total_chunks, key):
        try:
            with open(dest, "wb") as f:
                for idx in range(total_chunks):
                    c = self.api("GET", f"/api/files/{transfer_id}/chunk/{idx}")
                    plain = cc.decrypt(key, c["iv"], c["ct"])
                    f.write(base64.b64decode(plain))
            self.q.put(("download_done", transfer_id, dest))
        except Exception as e:
            try:
                os.remove(dest)
            except OSError:
                pass
            self.q.put(("download_error", transfer_id, str(e)))

    def on_key(self, event):
        if not self.peer or not self.ws or event.keysym == "Return" or time.time() - self.last_typing <= 1.5:
            return
        self.last_typing = time.time()
        what, who = self.peer
        try:
            if what == "dm":
                self.ws.send(json.dumps({"type": "typing", "to": who}))
            else:
                self.ws.send(json.dumps({"type": "gtyping", "group_id": who}))
        except Exception:
            pass

    def open_new_group(self):
        others = sorted(n for n in self.users if n != self.me)
        if len(others) < 1:
            return messagebox.showinfo(APP_NAME, "No other users to add yet.")
        win = tk.Toplevel(self.root)
        win.title("New group")
        win.geometry("280x380")
        tk.Label(win, text="Group name").pack(pady=(10, 0))
        name_entry = tk.Entry(win)
        name_entry.pack(fill="x", padx=10)
        tk.Label(win, text="Members").pack(pady=(10, 0))
        box = tk.Listbox(win, selectmode="multiple")
        for n in others:
            box.insert("end", n)
        box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        def create():
            name = name_entry.get().strip()
            picked = [others[i] for i in box.curselection()]
            if not name or not picked:
                return messagebox.showerror(APP_NAME, "Give the group a name and pick at least one member.")
            try:
                raw = cc.group_key_bytes()
                members = picked + [self.me]
                wrapped_keys = {m: cc.wrap_group_key(raw, self.priv, self.users[m]) for m in members}
                self.api("POST", "/api/groups", {"name": name, "wrapped_keys": wrapped_keys})
                win.destroy()
                self.load_groups_sync()
            except Exception as e:
                messagebox.showerror(APP_NAME, str(e))

        tk.Button(win, text="Create", command=create, bg=GREEN, fg="white", relief="flat").pack(pady=(0, 10))

    def open_status(self):
        win = tk.Toplevel(self.root)
        win.title("Status")
        win.geometry("340x420")
        tk.Label(win, text="What's on your mind?").pack(pady=(10, 2))
        entry = tk.Entry(win)
        entry.pack(fill="x", padx=10)
        box = tk.Text(win, state="disabled", wrap="word")
        box.pack(fill="both", expand=True, padx=10, pady=10)

        def refresh():
            try:
                items = self.api("GET", "/api/statuses")["statuses"]
            except Exception as e:
                items = []
                messagebox.showerror(APP_NAME, str(e))
            box.config(state="normal")
            box.delete("1.0", "end")
            for s in items:
                when = time.strftime("%d %b, %H:%M", time.localtime(s["ts"]))
                box.insert("end", f"{s['username']}  ({when})\n{s['text']}\n\n")
            box.config(state="disabled")

        def post():
            text = entry.get().strip()
            if not text:
                return
            try:
                self.api("POST", "/api/status", {"text": text})
                entry.delete(0, "end")
                refresh()
            except Exception as e:
                messagebox.showerror(APP_NAME, str(e))

        bar = tk.Frame(win)
        bar.pack(fill="x", padx=10)
        tk.Button(bar, text="Post status", command=post, bg=GREEN, fg="white", relief="flat").pack(side="left")
        tk.Button(bar, text="Refresh", command=refresh, relief="flat").pack(side="left", padx=6)
        tk.Label(win, text="Status text is visible to everyone and is not end-to-end encrypted. "
                           "It disappears after 24 hours.", wraplength=300, fg="#667781", justify="left").pack(
            padx=10, pady=(0, 6))
        refresh()

    def open_group_manage(self):
        if not self.peer or self.peer[0] != "group":
            return
        gid = self.peer[1]
        g = self.groups[gid]
        win = tk.Toplevel(self.root)
        win.title(g["name"] + " - Manage group")
        win.geometry("300x400")
        tk.Label(win, text="Members (you are the admin)", font=(FONT, 10, "bold")).pack(pady=(10, 4))
        members_frame = tk.Frame(win)
        members_frame.pack(fill="both", expand=True, padx=10)

        def remove(username):
            try:
                self.api("POST", f"/api/group/{gid}/remove", {"username": username})
                win.destroy()
                self.load_groups_sync()
            except Exception as e:
                messagebox.showerror(APP_NAME, str(e))

        for m in g["members"]:
            row = tk.Frame(members_frame)
            row.pack(fill="x", pady=2)
            label = m + ("  (admin)" if m == g["creator"] else "")
            tk.Label(row, text=label, anchor="w").pack(side="left", fill="x", expand=True)
            if m != self.me:
                tk.Button(row, text="Remove", fg="#c0392b", relief="flat",
                          command=lambda u=m: remove(u)).pack(side="right")

        tk.Label(win, text="Add a member").pack(pady=(14, 2))
        add_row = tk.Frame(win)
        add_row.pack(fill="x", padx=10)
        others = sorted(n for n in self.users if n not in g["members"])
        chosen = tk.StringVar(value=others[0] if others else "")
        if others:
            tk.OptionMenu(add_row, chosen, *others).pack(side="left", fill="x", expand=True)
        else:
            tk.Label(add_row, text="(everyone is already in this group)").pack(side="left")

        def add():
            username = chosen.get()
            if not username:
                return
            try:
                wrapped_key = cc.wrap_group_key(self.group_key_bytes(gid), self.priv, self.users[username])
                self.api("POST", f"/api/group/{gid}/add", {"username": username, "wrapped_key": wrapped_key})
                win.destroy()
                self.load_groups_sync()
            except Exception as e:
                messagebox.showerror(APP_NAME, str(e))

        if others:
            tk.Button(win, text="Add to group", command=add, bg=GREEN, fg="white",
                      relief="flat").pack(pady=10)

    def logout(self):
        self.token = None
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
        for w in self.root.winfo_children():
            w.destroy()
        self.reset_state()
        self.build_login()

    # ------------------------------------------------------------ live connection
    def ws_loop(self, token):
        url = SERVER.replace("http", "ws", 1) + "/ws"  # http -> ws, https -> wss
        while self.token == token:
            def on_open(ws):
                ws.send(json.dumps({"type": "auth", "token": token}))

            def on_message(ws, raw):
                try:
                    self.q.put(("ws", json.loads(raw)))
                except ValueError:
                    pass

            self.ws = websocket.WebSocketApp(url, on_open=on_open, on_message=on_message)
            self.ws.run_forever(ping_interval=20, ping_timeout=10)
            time.sleep(2)  # connection lost: wait, then reconnect

    def pump(self):
        """Runs every 100 ms on the screen thread and handles events from background threads."""
        try:
            while True:
                try:
                    self.handle(self.q.get_nowait())
                except queue.Empty:
                    break
                except Exception:
                    traceback.print_exc()
        finally:
            self.root.after(100, self.pump)

    def handle(self, ev):
        kind = ev[0]
        if kind == "authed":
            _, self.me, self.token, self.priv, self.my_pub = ev
            self.build_chat()
            try:
                self.load_users_sync()
            except Exception as e:
                self.sub.config(text=str(e))
            threading.Thread(target=self.ws_loop, args=(self.token,), daemon=True).start()
        elif kind == "autherr":
            self.say(ev[1])
            self.go_btn.config(state="normal")
        elif kind == "ws" and self.token:
            m, t = ev[1], ev[1].get("type")
            if t == "presence":
                self.online = set(m["online"])
                if any(n not in self.users for n in self.online):
                    self.load_users_sync()
                self.refresh_list()
            elif t == "msg":
                peer = m["receiver"] if m["sender"] == self.me else m["sender"]
                if peer not in self.users:
                    self.load_users_sync()
                row = ("dm", peer)
                if row == self.peer:
                    self.show_dm(m)
                elif m["sender"] != self.me:
                    self.unread[row] = self.unread.get(row, 0) + 1
                    self.refresh_list()
            elif t == "gmsg":
                gid, row = m["group_id"], ("group", m["group_id"])
                if gid not in self.groups:
                    self.load_groups_sync()
                if row == self.peer:
                    self.show_group(gid, m)
                elif m["sender"] != self.me:
                    self.unread[row] = self.unread.get(row, 0) + 1
                    self.refresh_list()
            elif t == "new_group":
                self.load_groups_sync()
            elif t == "group_updated":
                gid = m.get("group_id")
                if m.get("removed") and self.peer == ("group", gid):
                    messagebox.showinfo(APP_NAME, "You were removed from this group.")
                    self.peer = None
                    self.peer_label.config(text="Select a chat")
                    self.manage_btn.pack_forget()
                    self.clear_chat_view()
                self.group_keys.pop(gid, None)
                self.group_raw_keys.pop(gid, None)
                self.load_groups_sync()
            elif t == "new_file":
                threading.Thread(target=self.fetch_file_meta, args=(m["transfer_id"],), daemon=True).start()
            elif t == "typing" and self.peer == ("dm", m.get("from")):
                self.sub.config(text="typing...   " + self.base_sub)
                self.root.after(1500, lambda: self.sub.config(text=self.base_sub))
            elif t == "gtyping" and self.peer == ("group", m.get("group_id")):
                self.sub.config(text=m.get("from", "") + " is typing...   " + self.base_sub)
                self.root.after(1500, lambda: self.sub.config(text=self.base_sub))
        elif kind == "file_meta":
            _, transfer_id, meta = ev
            row = ("dm", meta["sender"]) if meta["kind"] == "dm" else ("group", int(meta["target"]))
            self.files[transfer_id] = {**meta, "row": row, "downloaded_path": None, "downloading": False}
            if row == self.peer:
                self.render_file_line(row, transfer_id)
            else:
                self.unread[row] = self.unread.get(row, 0) + 1
                self.refresh_list()
        elif kind == "upload_done":
            _, row, transfer_id, name, size, category = ev
            self.files[transfer_id] = {
                "transfer_id": transfer_id, "sender": self.me, "name": name, "size": size,
                "category": category, "ts": time.time(), "row": row,
                "downloaded_path": None, "downloading": False,
            }
            if row == self.peer:
                self.render_file_line(row, transfer_id)
        elif kind == "upload_error":
            _, row, name, err = ev
            self.append_note(row, f"\u26A0 Could not send {name}: {err}")
        elif kind == "download_done":
            _, transfer_id, path = ev
            info = self.files.get(transfer_id)
            if info:
                info["downloaded_path"], info["downloading"] = path, False
                if info.get("category") == "voice":
                    self.append_note(info["row"], "\u2705 Voice message ready")
                    try:
                        os.startfile(path)  # Windows: opens with the default audio player
                    except Exception:
                        self.append_note(info["row"], f"(saved to {path} \u2014 open it to listen)")
                else:
                    self.append_note(info["row"], f"\u2705 Saved \u201c{info['name']}\u201d to {path}")
        elif kind == "download_error":
            _, transfer_id, err = ev
            info = self.files.get(transfer_id)
            if info:
                info["downloading"] = False
            messagebox.showerror(APP_NAME, f"Could not download the file: {err}")


def main():
    root = tk.Tk()
    app = App(root)
    app.pump()
    root.mainloop()


if __name__ == "__main__":
    main()
