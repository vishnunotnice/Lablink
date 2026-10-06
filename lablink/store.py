"""SQLite transactions serialize enrollment and consume invitations atomically."""
import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from contextlib import contextmanager
from .system import private_write


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.db = self.directory / "state.sqlite3"
        fd = os.open(self.db, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(self.db, 0o600)
        with self.connect() as c:
            c.executescript("""CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, body TEXT);
CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, name TEXT UNIQUE, pubkey TEXT UNIQUE,
 ip TEXT UNIQUE, status TEXT, poll_hash TEXT, created REAL);
CREATE TABLE IF NOT EXISTS invites (token_hash TEXT PRIMARY KEY, expires REAL, request_id TEXT);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL, action TEXT, body TEXT);""")
        os.chmod(self.db, 0o600)

    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.db, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def event(self, c, action, **body):
        c.execute("INSERT INTO events(at,action,body) VALUES(?,?,?)", (time.time(), action, json.dumps(body)))

    def export_audit(self):
        # SQLite is the authoritative append-only application event stream.
        # JSONL is regenerated atomically to recover from an interrupted export.
        with self.connect() as c:
            rows = c.execute("SELECT * FROM events ORDER BY id").fetchall()
            private_write(self.directory / "audit.jsonl", "".join(json.dumps(dict(r)) + "\n" for r in rows))

    def config(self):
        with self.connect() as c:
            row = c.execute("SELECT body FROM config WHERE id=1").fetchone()
        if not row:
            raise ValueError("Hub is not initialized; run lablink init")
        return json.loads(row[0])

    def initialize(self, config):
        with self.connect() as c:
            if c.execute("SELECT 1 FROM config").fetchone():
                raise ValueError("Hub already initialized")
            c.execute("INSERT INTO config VALUES(1,?)", (json.dumps(config),))
            self.event(c, "hub_initialized", subnet=config['subnet'])
        self.export_audit()

    def nodes(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute("SELECT id,name,pubkey,ip,status,created FROM nodes ORDER BY created")]

    def invite(self, seconds):
        if not 0 < seconds <= 604800:
            raise ValueError("Invitation lifetime must be 1 second to 7 days")
        token = secrets.token_urlsafe(32)
        with self.connect() as c:
            c.execute("INSERT INTO invites VALUES(?,?,NULL)", (digest(token), time.time()+seconds))
            self.event(c, "invitation_created", lifetime_seconds=seconds)
        self.export_audit()
        return token

    def register(self, name, pubkey, token):
        from .system import identifier
        import base64
        identifier(name)
        try:
            if len(base64.b64decode(pubkey, validate=True)) != 32:
                raise ValueError()
        except Exception:
            raise ValueError("Invalid WireGuard public key") from None
        cfg = self.config()
        request_id, poll = uuid.uuid4().hex, secrets.token_urlsafe(32)
        with self.connect() as c:
            inv = c.execute("SELECT * FROM invites WHERE token_hash=?", (digest(token),)).fetchone()
            authorized = secrets.compare_digest(digest(token), cfg['token_hash'])
            if not authorized and (not inv or inv['expires'] < time.time() or inv['request_id']):
                raise ValueError("Invalid, expired, or consumed enrollment credential")
            existing = c.execute("SELECT status FROM nodes WHERE pubkey=?", (pubkey,)).fetchone()
            if existing:
                raise ValueError("Public key already registered or revoked")
            used = {r[0] for r in c.execute("SELECT ip FROM nodes")}
            address = next((str(ip) for ip in ipaddress.ip_network(cfg['subnet']).hosts()
                            if str(ip) not in used and str(ip) != cfg['hub_ip']), None)
            if not address:
                raise ValueError("Address pool exhausted")
            c.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?,?)",
                      (request_id,name,pubkey,address,'pending',digest(poll),time.time()))
            if inv:
                c.execute("UPDATE invites SET request_id=? WHERE token_hash=?", (request_id,digest(token)))
            self.event(c, "enrollment_requested", request_id=request_id,name=name,public_key=pubkey)
        self.export_audit()
        return {"request_id":request_id,"poll_token":poll,"status":"pending"}

    def poll(self, request_id, token):
        with self.connect() as c:
            node = c.execute("SELECT * FROM nodes WHERE id=?", (request_id,)).fetchone()
        if not node or not secrets.compare_digest(node['poll_hash'], digest(token)):
            raise ValueError("Unauthorized request")
        cfg = self.config()
        return {"status":node['status'],"ip":node['ip'],"hub_public_key":cfg['public_key'],
                "endpoint":cfg['endpoint'],"subnet":cfg['subnet']}

    def transition(self, request_id, status):
        with self.connect() as c:
            node=c.execute("SELECT * FROM nodes WHERE id=?", (request_id,)).fetchone()
            if not node:
                raise ValueError("Unknown request")
            if status == 'approved' and node['status'] != 'pending':
                raise ValueError("Only pending nodes can be approved")
            if status == 'revoked' and node['status'] == 'revoked':
                raise ValueError("Node already revoked")
            c.execute("UPDATE nodes SET status=? WHERE id=?",(status,request_id))
            self.event(c, "node_"+status, request_id=request_id)
        self.export_audit()
