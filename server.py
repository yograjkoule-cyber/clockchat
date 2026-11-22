"""
Secure chat server.

Security design
  * Passwords never reach the server. The app turns the password into two
    separate secrets (PBKDF2): one to log in, one to lock your private key.
    The server stores only a hash of the login secret.
  * Messages are end-to-end encrypted on your PC (ECDH P-256 + AES-256-GCM).
    The server only stores and forwards ciphertext - it cannot read messages.
  * Login tokens are signed and expire after 7 days.
  * Rate limits on login / register / sending, strict input checks,
    secret key generated randomly on first run.

Added in this version: groups with an admin, sending large files (up to 4 GB)
and voice messages, and status.
  * Group messages are end-to-end encrypted too: each group has its own random
    key, and that key is locked separately for every member with their own
    public key, the same way a one-to-one chat key is locked. The person who
    creates a group is its admin; only the admin can add or remove members.
  * A file (or a voice message, which is just an audio file) is split into
    small pieces (chunks) on your PC. Each piece is encrypted separately and
    uploaded on its own, so sending a huge file never needs to hold the whole
    thing in memory at once, on either side. The server stores the pieces and
    can see a file's name and size, but not its content.
  * Status text is NOT end-to-end encrypted (everyone can see everyone's
    status by design, like a notice board), and is deleted after 24 hours.

Running on your own PC:
    pip install flask flask-sock requests websocket-client cryptography
    python server.py        (then start client.py in another terminal)

Running on a host like Render so it is reachable over the internet:
    the host sets a PORT environment variable; this file automatically
    listens on 0.0.0.0 at that port when PORT is set, otherwise it listens
    only on localhost (127.0.0.1) for safety on your own PC.
"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time

from flask import Flask, jsonify, request
from flask_sock import Sock
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "chat.db")
KEY_FILE = os.path.join(BASE, "secret.key")
TOKEN_MAX_AGE = 7 * 24 * 3600

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def load_secret():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_FILE) as f:
        return f.read().strip()


TEXT_CT_MAX = 12_000          # a normal chat message, encrypted
STATUS_TTL = 24 * 3600

FILE_CHUNK_SIZE = 512 * 1024          # plaintext bytes per piece (512 KB)
FILE_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB, the overall limit on one file
FILE_CHUNK_CT_MAX = 1_200_000         # ciphertext text length limit per piece

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # one HTTP request's body; big files go in many small chunks
app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": 25}
sock = Sock(app)
signer = URLSafeTimedSerializer(load_secret(), salt="auth-token")
DUMMY_HASH = generate_password_hash("dummy")  # keeps login timing equal for unknown users


# ---------------------------------------------------------------- database
def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                auth_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                wrapped_key TEXT NOT NULL,
                created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL, receiver TEXT NOT NULL,
                iv TEXT NOT NULL, ct TEXT NOT NULL, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender, receiver);

            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, creator TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL, username TEXT NOT NULL,
                wrapped_key TEXT NOT NULL,
                PRIMARY KEY (group_id, username));
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL, sender TEXT NOT NULL,
                iv TEXT NOT NULL, ct TEXT NOT NULL, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_gmsg_group ON group_messages(group_id);

            CREATE TABLE IF NOT EXISTS statuses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL, text TEXT NOT NULL, ts REAL NOT NULL);

            CREATE TABLE IF NOT EXISTS file_transfers (
                transfer_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,            -- 'dm' or 'group'
                sender TEXT NOT NULL,
                target TEXT NOT NULL,          -- username (dm) or group id as text (group)
                name TEXT NOT NULL, size INTEGER NOT NULL,
                category TEXT NOT NULL DEFAULT 'file',  -- 'file' or 'voice'
                chunk_size INTEGER NOT NULL, total_chunks INTEGER NOT NULL,
                received_chunks INTEGER NOT NULL DEFAULT 0,
                complete INTEGER NOT NULL DEFAULT 0, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_file_target ON file_transfers(kind, target, complete);

            CREATE TABLE IF NOT EXISTS file_chunks (
                transfer_id TEXT NOT NULL, idx INTEGER NOT NULL,
                iv TEXT NOT NULL, ct TEXT NOT NULL,
                PRIMARY KEY (transfer_id, idx));
            """
        )
        # older databases from an earlier version of this app had extra columns here;
        # they are harmless and ignored, so no migration is needed.


def user_exists(name):
    with db() as c:
        return c.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone() is not None


# ---------------------------------------------------------------- helpers
_hits, _hits_lock = {}, threading.Lock()


def too_many(key, limit, window):
    """True if `key` did more than `limit` actions in the last `window` seconds."""
    now = time.time()
    with _hits_lock:
        recent = [t for t in _hits.get(key, []) if now - t < window]
        blocked = len(recent) >= limit
        if not blocked:
            recent.append(now)
        _hits[key] = recent
        return blocked


def make_token(username):
    return signer.dumps(username)


def read_token(token):
    try:
        return signer.loads(token, max_age=TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def current_user():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        name = read_token(header[7:])
        if name and user_exists(name):
            return name
    return None


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def error(msg, code=400):
    return jsonify(error=msg), code


def valid_public_key(s):
    try:
        j = json.loads(s)
        return (
            len(s) < 500 and j.get("kty") == "EC" and j.get("crv") == "P-256"
            and isinstance(j.get("x"), str) and isinstance(j.get("y"), str)
        )
    except Exception:
        return False


def valid_wrapped_key(s):
    try:
        j = json.loads(s)
        return len(s) < 4000 and isinstance(j.get("iv"), str) and isinstance(j.get("ct"), str)
    except Exception:
        return False


def is_group_member(group_id, user):
    with db() as c:
        return c.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND username=?", (group_id, user)
        ).fetchone() is not None


def group_member_names(group_id):
    with db() as c:
        return [r["username"] for r in c.execute(
            "SELECT username FROM group_members WHERE group_id=?", (group_id,))]


def get_group(group_id):
    with db() as c:
        return c.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()


def is_group_admin(group_id, user):
    g = get_group(group_id)
    return bool(g) and g["creator"] == user


def get_transfer(transfer_id):
    with db() as c:
        return c.execute("SELECT * FROM file_transfers WHERE transfer_id=?", (transfer_id,)).fetchone()


def can_access_transfer(t, user):
    if t["sender"] == user:
        return True
    if t["kind"] == "dm":
        return t["target"] == user
    try:
        return is_group_member(int(t["target"]), user)
    except ValueError:
        return False


def transfer_recipients(t):
    """Everyone who should be notified when a transfer finishes uploading."""
    if t["kind"] == "dm":
        return [t["target"]] if t["target"] != t["sender"] else []
    try:
        return [m for m in group_member_names(int(t["target"])) if m != t["sender"]]
    except ValueError:
        return []


# ---------------------------------------------------------------- API
@app.post("/api/register")
def register():
    if too_many("reg:" + str(request.remote_addr), 20, 3600):
        return error("Too many attempts. Try again later.", 429)
    d = body()
    username = str(d.get("username", "")).lower()
    auth, pub, wrapped = d.get("auth", ""), d.get("public_key", ""), d.get("wrapped_key", "")
    if not USERNAME_RE.match(username):
        return error("Username must be 3-20 characters: a-z, 0-9, _")
    if not (isinstance(auth, str) and HEX64_RE.match(auth)):
        return error("Invalid request")
    if not (isinstance(pub, str) and valid_public_key(pub)):
        return error("Invalid public key")
    if not (isinstance(wrapped, str) and valid_wrapped_key(wrapped)):
        return error("Invalid key data")
    try:
        with db() as c:
            c.execute(
                "INSERT INTO users(username, auth_hash, public_key, wrapped_key, created) VALUES (?,?,?,?,?)",
                (username, generate_password_hash(auth), pub, wrapped, time.time()),
            )
    except sqlite3.IntegrityError:
        return error("That username is taken", 409)
    return jsonify(token=make_token(username))


@app.post("/api/login")
def login():
    d = body()
    username = str(d.get("username", "")).lower()
    auth = d.get("auth", "")
    if too_many(f"login:{request.remote_addr}:{username}", 10, 60):
        return error("Too many attempts. Wait a minute.", 429)
    if not (isinstance(auth, str) and HEX64_RE.match(auth)):
        return error("Invalid request")
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ok = check_password_hash(row["auth_hash"] if row else DUMMY_HASH, auth)
    if not (row and ok):
        return error("Wrong username or password", 401)
    return jsonify(token=make_token(username), public_key=row["public_key"], wrapped_key=row["wrapped_key"])


@app.get("/api/users")
def users():
    if not current_user():
        return error("Not logged in", 401)
    with db() as c:
        rows = c.execute("SELECT username, public_key FROM users ORDER BY username").fetchall()
    with clients_lock:
        online = list(clients.keys())
    return jsonify(users=[dict(r) for r in rows], online=online)


def file_item(r):
    return {"msgkind": "file", "transfer_id": r["transfer_id"], "sender": r["sender"],
            "name": r["name"], "size": r["size"], "category": r["category"],
            "chunk_size": r["chunk_size"], "total_chunks": r["total_chunks"], "ts": r["ts"]}


@app.get("/api/history/<peer>")
def history(peer):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    if not USERNAME_RE.match(peer):
        return error("Invalid user")
    with db() as c:
        msgs = c.execute(
            """SELECT sender, receiver, iv, ct, ts FROM messages
               WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
               ORDER BY id DESC LIMIT 500""",
            (me, peer, peer, me),
        ).fetchall()
        files = c.execute(
            """SELECT * FROM file_transfers WHERE kind='dm' AND complete=1 AND
               ((sender=? AND target=?) OR (sender=? AND target=?))
               ORDER BY ts DESC LIMIT 200""",
            (me, peer, peer, me),
        ).fetchall()
    items = [{"msgkind": "text", **dict(r)} for r in msgs] + [file_item(r) for r in files]
    items.sort(key=lambda x: x["ts"])
    return jsonify(items=items)


# ---------------------------------------------------------------- groups
@app.post("/api/groups")
def create_group():
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    d = body()
    name = str(d.get("name", "")).strip()[:40]
    wrapped_keys = d.get("wrapped_keys")  # {username: wrapped_key_json}, must include me
    if not name:
        return error("Group needs a name")
    if not (isinstance(wrapped_keys, dict) and me in wrapped_keys):
        return error("Missing keys for members")
    members = list(wrapped_keys.keys())
    if not (2 <= len(members) <= 50 and all(USERNAME_RE.match(m) for m in members)):
        return error("Invalid member list")
    for m in members:
        if not user_exists(m):
            return error(f"Unknown user: {m}")
        if not valid_wrapped_key(str(wrapped_keys[m])):
            return error("Invalid key data")
    with db() as c:
        gid = c.execute(
            "INSERT INTO groups(name, creator, created) VALUES (?,?,?)", (name, me, time.time())
        ).lastrowid
        for m in members:
            c.execute(
                "INSERT INTO group_members(group_id, username, wrapped_key) VALUES (?,?,?)",
                (gid, m, wrapped_keys[m]),
            )
    for m in members:
        push(m, {"type": "new_group", "group_id": gid})
    return jsonify(group_id=gid)


@app.post("/api/group/<int:gid>/add")
def add_group_member(gid):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    if not is_group_admin(gid, me):
        return error("Only the group admin can add members", 403)
    d = body()
    username = str(d.get("username", ""))
    wrapped_key = d.get("wrapped_key")
    if not (USERNAME_RE.match(username) and user_exists(username)):
        return error("Unknown user")
    if not valid_wrapped_key(str(wrapped_key)):
        return error("Invalid key data")
    if is_group_member(gid, username):
        return error("Already a member", 409)
    with db() as c:
        c.execute(
            "INSERT INTO group_members(group_id, username, wrapped_key) VALUES (?,?,?)",
            (gid, username, wrapped_key),
        )
    for member in group_member_names(gid):
        push(member, {"type": "group_updated", "group_id": gid})
    return jsonify(ok=True)


@app.post("/api/group/<int:gid>/remove")
def remove_group_member(gid):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    if not is_group_admin(gid, me):
        return error("Only the group admin can remove members", 403)
    username = str(body().get("username", ""))
    if username == me:
        return error("The admin can't remove themselves")
    if not is_group_member(gid, username):
        return error("That person isn't in the group")
    with db() as c:
        c.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (gid, username))
    push(username, {"type": "group_updated", "group_id": gid, "removed": True})
    for member in group_member_names(gid):
        push(member, {"type": "group_updated", "group_id": gid})
    return jsonify(ok=True)


@app.get("/api/groups")
def my_groups():
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    with db() as c:
        rows = c.execute(
            """SELECT g.id, g.name, g.creator, gm.wrapped_key FROM groups g
               JOIN group_members gm ON gm.group_id = g.id WHERE gm.username=?""",
            (me,),
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r["id"], "name": r["name"], "creator": r["creator"], "wrapped_key": r["wrapped_key"],
                "members": group_member_names(r["id"]),
            })
    return jsonify(groups=out)


@app.get("/api/group/<int:gid>/history")
def group_history(gid):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    if not is_group_member(gid, me):
        return error("Not a member of this group", 403)
    with db() as c:
        msgs = c.execute(
            """SELECT sender, iv, ct, ts FROM group_messages
               WHERE group_id=? ORDER BY id DESC LIMIT 500""",
            (gid,),
        ).fetchall()
        files = c.execute(
            """SELECT * FROM file_transfers WHERE kind='group' AND target=? AND complete=1
               ORDER BY ts DESC LIMIT 200""",
            (str(gid),),
        ).fetchall()
    items = [{"msgkind": "text", **dict(r)} for r in msgs] + [file_item(r) for r in files]
    items.sort(key=lambda x: x["ts"])
    return jsonify(items=items)


# ---------------------------------------------------------------- status
@app.post("/api/status")
def post_status():
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    text = str(body().get("text", "")).strip()[:280]
    if not text:
        return error("Status cannot be empty")
    if too_many("status:" + me, 10, 3600):
        return error("Too many statuses. Try again later.", 429)
    with db() as c:
        c.execute("INSERT INTO statuses(username, text, ts) VALUES (?,?,?)", (me, text, time.time()))
        c.execute("DELETE FROM statuses WHERE ts < ?", (time.time() - STATUS_TTL,))
    return jsonify(ok=True)


@app.get("/api/statuses")
def list_statuses():
    if not current_user():
        return error("Not logged in", 401)
    with db() as c:
        rows = c.execute(
            "SELECT username, text, ts FROM statuses WHERE ts >= ? ORDER BY ts DESC",
            (time.time() - STATUS_TTL,),
        ).fetchall()
    return jsonify(statuses=[dict(r) for r in rows])


# ---------------------------------------------------------------- file transfers
@app.post("/api/files")
def start_file():
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    d = body()
    kind = d.get("kind")
    name = str(d.get("name", "")).strip()[:150]
    size = d.get("size")
    category = d.get("category", "file")
    if category not in ("file", "voice"):
        return error("Invalid category")
    if too_many("filenew:" + me, 20, 3600):
        return error("Too many files started. Try again later.", 429)
    if not (isinstance(size, int) and 0 <= size <= FILE_MAX_BYTES):
        return error(f"File must be under {FILE_MAX_BYTES // (1024*1024*1024)} GB")
    if not name or "/" in name or "\\" in name:
        return error("Invalid file name")
    if kind == "dm":
        target = str(d.get("to", ""))
        if not (USERNAME_RE.match(target) and user_exists(target)):
            return error("Unknown user")
    elif kind == "group":
        gid = d.get("group_id")
        if not (isinstance(gid, int) and is_group_member(gid, me)):
            return error("Not a member of that group")
        target = str(gid)
    else:
        return error("Invalid kind")
    total_chunks = max(1, -(-size // FILE_CHUNK_SIZE))  # ceiling division
    transfer_id = secrets.token_hex(16)
    with db() as c:
        c.execute(
            """INSERT INTO file_transfers(transfer_id, kind, sender, target, name, size,
               category, chunk_size, total_chunks, ts) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (transfer_id, kind, me, target, name, size, category, FILE_CHUNK_SIZE, total_chunks, time.time()),
        )
    return jsonify(transfer_id=transfer_id, chunk_size=FILE_CHUNK_SIZE, total_chunks=total_chunks)


@app.post("/api/files/<transfer_id>/chunk/<int:idx>")
def upload_chunk(transfer_id, idx):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    t = get_transfer(transfer_id)
    if not t or t["sender"] != me:
        return error("Unknown transfer", 404)
    if t["complete"]:
        return jsonify(ok=True)  # already finished; treat a repeat as harmless
    if not (0 <= idx < t["total_chunks"]):
        return error("Invalid chunk number")
    d = body()
    iv, ct = d.get("iv"), d.get("ct")
    if not (isinstance(iv, str) and isinstance(ct, str) and B64_RE.match(iv) and B64_RE.match(ct)):
        return error("Invalid chunk data")
    if len(iv) > 32 or len(ct) > FILE_CHUNK_CT_MAX:
        return error("Chunk too large")
    if too_many("filechunk:" + me, 3000, 60):
        return error("Sending too fast. Pausing briefly.", 429)
    with db() as c:
        c.execute(
            "INSERT OR IGNORE INTO file_chunks(transfer_id, idx, iv, ct) VALUES (?,?,?,?)",
            (transfer_id, idx, iv, ct),
        )
        count = c.execute(
            "SELECT COUNT(*) AS n FROM file_chunks WHERE transfer_id=?", (transfer_id,)
        ).fetchone()["n"]
        done = count >= t["total_chunks"]
        c.execute(
            "UPDATE file_transfers SET received_chunks=?, complete=? WHERE transfer_id=?",
            (count, 1 if done else 0, transfer_id),
        )
    if done:
        for name in transfer_recipients(t):
            push(name, {"type": "new_file", "transfer_id": transfer_id})
    return jsonify(ok=True, received=count, total=t["total_chunks"])


@app.get("/api/files/<transfer_id>")
def file_meta(transfer_id):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    t = get_transfer(transfer_id)
    if not t or not can_access_transfer(t, me):
        return error("Not found", 404)
    return jsonify(dict(t))


@app.get("/api/files/<transfer_id>/chunk/<int:idx>")
def download_chunk(transfer_id, idx):
    me = current_user()
    if not me:
        return error("Not logged in", 401)
    t = get_transfer(transfer_id)
    if not t or not can_access_transfer(t, me):
        return error("Not found", 404)
    with db() as c:
        row = c.execute(
            "SELECT iv, ct FROM file_chunks WHERE transfer_id=? AND idx=?", (transfer_id, idx)
        ).fetchone()
    if not row:
        return error("Chunk not available", 404)
    return jsonify(iv=row["iv"], ct=row["ct"])


# ---------------------------------------------------------------- WebSocket
clients, clients_lock = {}, threading.Lock()  # username -> set of sockets
send_lock = threading.Lock()


def push(username, payload):
    with clients_lock:
        targets = list(clients.get(username, ()))
    text = json.dumps(payload)
    for w in targets:
        try:
            with send_lock:
                w.send(text)
        except Exception:
            pass


def push_presence():
    with clients_lock:
        names = list(clients.keys())
    for n in names:
        push(n, {"type": "presence", "online": names})


def handle_message(user, raw):
    try:
        m = json.loads(raw)
    except ValueError:
        return
    if not isinstance(m, dict):
        return
    t = m.get("type")

    if t == "typing":
        to = m.get("to")
        if isinstance(to, str) and USERNAME_RE.match(to):
            push(to, {"type": "typing", "from": user})
        return

    if t == "gtyping":
        gid = m.get("group_id")
        if isinstance(gid, int) and is_group_member(gid, user):
            for name in group_member_names(gid):
                if name != user:
                    push(name, {"type": "gtyping", "group_id": gid, "from": user})
        return

    if t == "msg":
        to = m.get("to")
        if not (isinstance(to, str) and USERNAME_RE.match(to) and user_exists(to)):
            return
        iv, ct = m.get("iv"), m.get("ct")
        if not (isinstance(iv, str) and isinstance(ct, str) and B64_RE.match(iv) and B64_RE.match(ct)):
            return
        if len(iv) > 32 or len(ct) > TEXT_CT_MAX:
            return
        if too_many("send:" + user, 30, 10):
            return
        ts = time.time()
        with db() as c:
            c.execute(
                "INSERT INTO messages(sender, receiver, iv, ct, ts) VALUES (?,?,?,?,?)",
                (user, to, iv, ct, ts),
            )
        out = {"type": "msg", "sender": user, "receiver": to, "iv": iv, "ct": ct, "ts": ts}
        push(to, out)
        if to != user:
            push(user, out)
        return

    if t == "gmsg":
        gid = m.get("group_id")
        if not (isinstance(gid, int) and is_group_member(gid, user)):
            return
        iv, ct = m.get("iv"), m.get("ct")
        if not (isinstance(iv, str) and isinstance(ct, str) and B64_RE.match(iv) and B64_RE.match(ct)):
            return
        if len(iv) > 32 or len(ct) > TEXT_CT_MAX:
            return
        if too_many("send:" + user, 30, 10):
            return
        ts = time.time()
        with db() as c:
            c.execute(
                "INSERT INTO group_messages(group_id, sender, iv, ct, ts) VALUES (?,?,?,?,?)",
                (gid, user, iv, ct, ts),
            )
        out = {"type": "gmsg", "group_id": gid, "sender": user, "iv": iv, "ct": ct, "ts": ts}
        for member in group_member_names(gid):
            push(member, out)
        return


@sock.route("/ws")
def ws_route(ws):
    try:
        first = json.loads(ws.receive(timeout=10) or "{}")
        user = read_token(first.get("token", "")) if first.get("type") == "auth" else None
    except Exception:
        user = None
    if not (user and user_exists(user)):
        ws.close()
        return
    with clients_lock:
        clients.setdefault(user, set()).add(ws)
    push_presence()
    try:
        while True:
            raw = ws.receive()
            if raw is None or len(raw) > TEXT_CT_MAX + 2000:
                continue
            handle_message(user, raw)
    except Exception:
        pass
    finally:
        with clients_lock:
            clients.get(user, set()).discard(ws)
            if not clients.get(user):
                clients.pop(user, None)
        push_presence()


if __name__ == "__main__":
    init_db()
    cert, key = os.path.join(BASE, "cert.pem"), os.path.join(BASE, "key.pem")
    https = os.path.exists(cert) and os.path.exists(key)
    # A hosting platform like Render sets PORT and expects 0.0.0.0; on your own
    # PC there is no PORT, so it stays on localhost only, which is safer.
    port = int(os.environ.get("PORT", 5000))
    default_host = "0.0.0.0" if "PORT" in os.environ else "127.0.0.1"
    host = os.environ.get("CHAT_HOST", default_host)
    print(f"Server running on port {port} ({'reachable over the internet' if host == '0.0.0.0' else 'localhost only'})")
    app.run(host=host, port=port, threaded=True, ssl_context=(cert, key) if https else None)
