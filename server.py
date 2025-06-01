#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import shutil
import threading
import itertools
import time
import socket
import ssl
import ipaddress
import urllib.request
import re
import select

from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import http.client

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, SubjectAlternativeName, DNSName
import cryptography.x509 as x509

# ─── CONSTANTS ─────────────────────────────────────────────────────────────────
SCRIPT_PATH    = os.path.abspath(__file__)
SCRIPT_DIR     = os.path.dirname(SCRIPT_PATH)
CONFIG_PATH    = os.path.join(SCRIPT_DIR, "config.json")
DOMAIN_CONF    = os.path.join(SCRIPT_DIR, "domain.conf")
VENV_FLAG      = "--in-venv"
VENV_DIR       = os.path.join(SCRIPT_DIR, "venv")

# Base port for Node; if 3000 is busy, we’ll increment
BASE_APP_PORT  = 3000

# Local HTTPS reverse-proxy for “dev” (forward 9443 → Node)
DEV_HTTPS_PORT = 9443

# Default TTL for Cloudflare DNS records (seconds)
DEFAULT_TTL    = 300


# ─── SPINNER (for long installs) ───────────────────────────────────────────────
class Spinner:
    def __init__(self, msg):
        self.msg, self.spin = msg, itertools.cycle("|/-\\")
        self._stop = threading.Event()
        self._thr  = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            sys.stdout.write(f"\r{self.msg} {next(self.spin)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.msg) + 2) + "\r")
        sys.stdout.flush()

    def __enter__(self):
        self._thr.start()

    def __exit__(self, *args):
        self._stop.set()
        self._thr.join()


# ─── 1) VIRTUALENV BOOTSTRAP ────────────────────────────────────────────────────
def bootstrap_and_run():
    """
    If we’re not already in our venv, create/use venv, install Python deps,
    then re-launch this script with --in-venv so all imports work.
    """
    if VENV_FLAG not in sys.argv:
        if not os.path.isdir(VENV_DIR):
            with Spinner("Creating virtualenv…"):
                subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
        pip_exe = os.path.join(VENV_DIR, "bin", "pip")
        with Spinner("Installing dependencies…"):
            subprocess.check_call([pip_exe, "install", "cryptography", "requests"])
        py_exe = os.path.join(VENV_DIR, "bin", "python")
        os.execv(py_exe, [py_exe, SCRIPT_PATH, VENV_FLAG] + sys.argv[1:])
    else:
        sys.argv.remove(VENV_FLAG)
        main()


# ─── 2) CONFIG I/O ─────────────────────────────────────────────────────────────
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            return json.load(open(CONFIG_PATH))
        except:
            pass
    return {"serve_path": os.getcwd()}

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=4)


# ─── 3) DOMAIN.CONF I/O ────────────────────────────────────────────────────────
def create_domain_conf():
    """
    Prompt user to choose DEV vs PRODUCTION. 
    If PRODUCTION, ask for Cloudflare API token + zone name + subdomain + TTL. 
    Save these in domain.conf.
    """
    print("\n⚠  Do you want to run in DEV mode or PRODUCTION mode?")
    print("   1) DEV (no Cloudflare, just random Serveo subdomain)")
    print("   2) PRODUCTION (Cloudflare + custom subdomain)")
    choice = input("Enter 1 or 2: ").strip()
    if choice not in ("1", "2"):
        print("Invalid choice—please run again and choose 1 or 2.")
        sys.exit(1)

    if choice == "1":
        # DEV mode: no DNS changes needed
        conf = {
            "mode": "dev"
        }
        with open(DOMAIN_CONF, "w") as f:
            json.dump(conf, f, indent=4)
        print("\n✅ Running in DEV mode. No DNS changes will be made.\n")
        return conf

    # PRODUCTION path:
    print("\n⚠  Before proceeding, make sure you have a Cloudflare API Token with “Edit zone DNS” permissions for your zone.\n")
    cf_token   = input("  Cloudflare API Token     : ").strip()
    zone_name  = input("  Cloudflare Zone Name     : ").strip()
    host       = input("  Subdomain (e.g. chat)    : ").strip() or "www"
    ttl_s      = input(f"  DNS TTL (secs) [{DEFAULT_TTL}]: ").strip() or str(DEFAULT_TTL)
    try:
        ttl = int(ttl_s)
    except:
        ttl = DEFAULT_TTL

    # Fetch the zone ID from Cloudflare
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }
    resp = requests.get(
        "https://api.cloudflare.com/client/v4/zones",
        params={"name": zone_name, "status": "active"},
        headers=headers,
        timeout=10
    )
    data = resp.json()
    if not data.get("success") or len(data.get("result", [])) == 0:
        print(f"❌ Unable to find active zone '{zone_name}' in Cloudflare. Response: {data}")
        sys.exit(1)
    zone_id = data["result"][0]["id"]

    conf = {
        "mode":       "prod",
        "cf_token":   cf_token,
        "zone_id":    zone_id,
        "zone_name":  zone_name,
        "host":       host,
        "ttl":        ttl
    }
    with open(DOMAIN_CONF, "w") as f:
        json.dump(conf, f, indent=4)
    print("\n✅ domain.conf created. Will use these credentials to update DNS soon.\n")
    return conf

def load_domain_conf():
    if not os.path.exists(DOMAIN_CONF):
        return create_domain_conf()
    return json.load(open(DOMAIN_CONF))


# ─── 4) HELPERS ─────────────────────────────────────────────────────────────────
def get_lan_ip():
    """Return the machine’s LAN IPv4 address by opening a UDP socket to 8.8.8.8."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def get_public_ip():
    """Try to fetch your public IP from api.ipify.org. If that fails, return None."""
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
    except:
        return None

def port_in_use(port: int) -> bool:
    """Return True if anything is already bound on 0.0.0.0:<port>."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return False
        except OSError:
            return True


# ─── 5) BANNER ─────────────────────────────────────────────────────────────────
def print_banner(lan_ip: str, public_domain: str, app_port: int):
    """
    Show where your service is listening:
      • Node (HTTP)  → http://127.0.0.1:<app_port>
      • Local Dev    → https://localhost:9443
      • LAN Dev      → https://<lan_ip>:9443
      • Production   → https://<public_domain>
    """
    lines = [
        f"  Node (HTTP)  → http://127.0.0.1:{app_port}",
        f"  Local Dev    → https://localhost:{DEV_HTTPS_PORT}",
        f"  LAN Dev      → https://{lan_ip}:{DEV_HTTPS_PORT}",
        f"  Production   → https://{public_domain}"
    ]
    w = max(len(l) for l in lines) + 4
    print("\n╔" + "═"*w + "╗")
    for l in lines:
        print("║" + l.ljust(w) + "║")
    print("╚" + "═"*w + "╝\n")


# ─── 6) SSH KEY + FINGERPRINT ───────────────────────────────────────────────────
def ensure_ssh_key():
    """
    If ~/.ssh/id_rsa.pub is missing, generate a new 2048-bit RSA key.
    Return the SHA256 fingerprint (without the “SHA256:” prefix).
    """
    ssh_dir      = os.path.expanduser("~/.ssh")
    pubkey_path  = os.path.join(ssh_dir, "id_rsa.pub")
    privkey_path = os.path.join(ssh_dir, "id_rsa")

    if not os.path.isdir(ssh_dir):
        os.makedirs(ssh_dir, mode=0o700)

    if not os.path.exists(pubkey_path):
        print("⚠ No SSH key found at ~/.ssh/id_rsa.pub; generating a new 2048-bit RSA key…")
        cmd = ["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", privkey_path, "-N", ""]
        subprocess.check_call(cmd)
        print(f"✅ SSH keypair generated at {privkey_path} and {pubkey_path}")

    # Compute SHA256 fingerprint via ssh-keygen
    try:
        out = subprocess.check_output(
            ["ssh-keygen", "-lf", pubkey_path, "-E", "sha256"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        # Typical output: "2048 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef user@host (RSA)"
        m = re.search(r"SHA256:([A-Za-z0-9+/=]+)", out)
        if not m:
            raise RuntimeError(f"Could not parse fingerprint from: {out}")
        fingerprint = m.group(1)
    except Exception as e:
        raise RuntimeError(f"Unable to compute SSH key fingerprint: {e}")

    print("\n🔑 Your SSH public-key fingerprint (SHA256) is:\n")
    print(f"    SHA256:{fingerprint}\n")
    print("✅ Will push this fingerprint as a TXT record via Cloudflare API—no manual step required.\n")
    return fingerprint


# ─── 7) CERTIFICATE GENERATION ─────────────────────────────────────────────────
def generate_cert(cert_file: str, key_file: str, real_domain: str, tunnel_domain: str):
    """
    Generate a multi-SAN certificate covering:
      • localhost
      • <LAN_IP>
      • <real_domain>   (e.g. chat.hypermindlabs.org)
      • <tunnel_domain> (e.g. abc123.serveo.net)
      • 127.0.0.1

    If mkcert is present, use it; otherwise fallback to a self-signed from cryptography.
    Overwrites existing files if present.
    """
    lan_ip = get_lan_ip()

    # Remove old cert/key if they exist
    if os.path.exists(cert_file):
        os.remove(cert_file)
    if os.path.exists(key_file):
        os.remove(key_file)

    if shutil.which("mkcert"):
        subprocess.run(["mkcert", "-install"], check=True)
        subprocess.run([
            "mkcert",
            "-cert-file", cert_file,
            "-key-file", key_file,
            "localhost",
            lan_ip,
            real_domain,
            tunnel_domain,
            "127.0.0.1"
        ], check=True)
        return

    keyobj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName(lan_ip),
        x509.DNSName(real_domain),
        x509.DNSName(tunnel_domain),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
    ])
    name = x509.Name([ x509.NameAttribute(NameOID.COMMON_NAME, real_domain) ])
    cert = (
        x509.CertificateBuilder()
           .subject_name(name)
           .issuer_name(name)
           .public_key(keyobj.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(datetime.utcnow())
           .not_valid_after(datetime.utcnow() + timedelta(days=365))
           .add_extension(san, critical=False)
           .sign(keyobj, hashes.SHA256())
    )

    with open(key_file, "wb") as f:
        f.write(keyobj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


# ─── 8) REVERSE PROXY HANDLER (local HTTPS→Node) ────────────────────────────────
class ReverseProxyHandler(BaseHTTPRequestHandler):
    """
    Any request arriving on https://localhost:9443 will be forwarded to
    http://127.0.0.1:<app_port> by this handler. We attach app_port to the server.
    """
    def _proxy(self):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.server.app_port, timeout=10)
            path = self.path
            headers = {k: v for k, v in self.headers.items()}
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else None

            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()

            self.send_response(resp.status, resp.reason)
            for h, v in resp.getheaders():
                if h.lower() not in (
                    "transfer-encoding", "connection", "keep-alive",
                    "proxy-authenticate", "proxy-authorization",
                    "te", "trailers", "upgrade"
                ):
                    self.send_header(h, v)
            self.end_headers()

            data = resp.read()
            if data:
                self.wfile.write(data)
            conn.close()
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")

    def do_GET(self):     self._proxy()
    def do_POST(self):    self._proxy()
    def do_PUT(self):     self._proxy()
    def do_DELETE(self):  self._proxy()
    def do_PATCH(self):   self._proxy()
    def do_OPTIONS(self): self._proxy()
    def do_HEAD(self):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.server.app_port, timeout=10)
            conn.request("HEAD", self.path, headers={k: v for k, v in self.headers.items()})
            resp = conn.getresponse()
            self.send_response(resp.status, resp.reason)
            for h, v in resp.getheaders():
                if h.lower() not in (
                    "transfer-encoding", "connection", "keep-alive",
                    "proxy-authenticate", "proxy-authorization",
                    "te", "trailers", "upgrade"
                ):
                    self.send_header(h, v)
            self.end_headers()
            conn.close()
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")


# ─── 9) START LOCAL DEV HTTPS (9443) ───────────────────────────────────────────
def start_local_https(cert_file: str, key_file: str, app_port: int):
    """
    If DEV_HTTPS_PORT (9443) is free, bind an HTTPS server there
    using ReverseProxyHandler (forward to 127.0.0.1:<app_port>).
    """
    if port_in_use(DEV_HTTPS_PORT):
        print(f"⚠ Local HTTPS port {DEV_HTTPS_PORT} in use; skipping local HTTPS reverse-proxy.")
        return

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    handler = ReverseProxyHandler
    httpd = HTTPServer(("0.0.0.0", DEV_HTTPS_PORT), handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.app_port = app_port

    threading.Thread(target=httpd.serve_forever, daemon=True).start()


# ─── 10) START SERVEO TUNNEL ─────────────────────────────────────────────────────
def start_serveo_tunnel(timeout: int, app_port: int, real_domain: str=None) -> str:
    """
    Run either:
      • ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -R 80:localhost:<app_port> serveo.net        (DEV mode),
      • or ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -R <real_domain>:80:localhost:<app_port> serveo.net   (PROD mode).

    Wait up to `timeout` seconds for a line like:
      "Forwarding HTTP traffic from https://<hostname> to localhost:<app_port>"
    If found, return "<hostname>". Else kill SSH and return None.
    """
    if shutil.which("ssh") is None:
        print("⚠ `ssh` not found; cannot establish Serveo tunnel.")
        return None

    if real_domain:
        # PRODUCTION: ask Serveo to bind custom domain
        forward_arg = f"{real_domain}:80:localhost:{app_port}"
    else:
        # DEV: random ephemeral subdomain
        forward_arg = f"80:localhost:{app_port}"

    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ExitOnForwardFailure=yes",
        "-R", forward_arg,
        "serveo.net"
    ]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        print(f"⚠ Failed to start SSH: {e}")
        return None

    host = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([p.stdout], [], [], 0.5)
        if ready:
            line = p.stdout.readline()
            if not line:
                continue
            # For DEV: “Forwarding HTTP traffic from https://xyz123.serveo.net to localhost:<port>”
            # For PROD: “Forwarding HTTP traffic from https://chat.example.com to localhost:<port>”
            m = re.search(r"Forwarding\s+HTTP\s+traffic\s+from\s+https?://([\w\-.]+)", line)
            if m:
                host = m.group(1).strip()
                break

    if not host:
        try:
            p.kill()
        except:
            pass
        print("⚠ Serveo tunnel failed or timed out.")
        return None

    print(f"✅ Serveo tunnel established: https://{host}")
    return host


# ─── 11) UPDATE CLOUDFLARE CNAME + TXT ───────────────────────────────────────────
def update_cloudflare(conf: dict, cname_target: str, txt_value: str):
    """
    Use Cloudflare’s API to set/update two DNS records in the specified zone:
      1) CNAME record at <host>.<zone_name> → serveo.net (i.e. cname_target = "serveo.net")
      2) TXT    record at _serveo-authkey.<host>.<zone_name> → txt_value

    Both are applied individually via Cloudflare API.
    """
    token    = conf["cf_token"]
    zone_id  = conf["zone_id"]
    zone     = conf["zone_name"]
    host     = conf["host"]
    ttl      = conf.get("ttl", DEFAULT_TTL)

    full_name       = f"{host}.{zone}"
    txt_record_name = f"_serveo-authkey.{host}.{zone}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }

    def upsert_record(record_type: str, name: str, content: str, proxied: bool=False):
        # 1) Check if an existing record exists
        params = {
            "type": record_type,
            "name": name
        }
        r = requests.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            params=params,
            headers=headers,
            timeout=10
        )
        data = r.json()
        if not data.get("success"):
            print(f"⚠ Cloudflare API error listing {record_type} records for {name}: {data}")
            return

        existing = data.get("result", [])
        payload = {
            "type":    record_type,
            "name":    name,
            "content": content,
            "ttl":     ttl,
            "proxied": proxied if record_type == "CNAME" else False
        }

        if existing:
            rec_id = existing[0]["id"]
            resp = requests.put(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
                headers=headers,
                json=payload,
                timeout=10
            )
            resp_data = resp.json()
            if resp_data.get("success"):
                print(f"[Cloudflare] Updated {record_type} record {name} → {content}  (TTL={ttl})")
            else:
                print(f"⚠ Cloudflare failed to update {record_type} {name}: {resp_data}")
        else:
            resp = requests.post(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                headers=headers,
                json=payload,
                timeout=10
            )
            resp_data = resp.json()
            if resp_data.get("success"):
                print(f"[Cloudflare] Created {record_type} record {name} → {content}  (TTL={ttl})")
            else:
                print(f"⚠ Cloudflare failed to create {record_type} {name}: {resp_data}")

    # Upsert CNAME: chat.example.com → serveo.net  (proxied=False)
    upsert_record("CNAME", full_name, cname_target, proxied=False)

    # Upsert TXT: _serveo-authkey.chat.example.com → SHA256:<fingerprint>
    upsert_record("TXT", txt_record_name, txt_value, proxied=False)


# ─── 12) HEALTH-CHECK ROUTINES ──────────────────────────────────────────────────
def self_test_once(real_domain: str, app_port: int):
    """
    Run one round of health checks:
      1) http://127.0.0.1:<app_port>/
      2) https://localhost:9443/
      3) https://<LAN_IP>:9443/
      4) https://<real_domain>/
    """
    lan_ip = get_lan_ip()
    tests = [
        (f"http://127.0.0.1:{app_port}/",        False),
        (f"https://localhost:{DEV_HTTPS_PORT}/", False),
        (f"https://{lan_ip}:{DEV_HTTPS_PORT}/",  False),
        (f"https://{real_domain}/",              False),
    ]
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Health-check:")
    for url, verify in tests:
        try:
            r = requests.get(url, timeout=5, verify=verify)
            print(f"  [HEALTHCHK] {url} → {r.status_code}")
        except Exception as e:
            print(f"  [HEALTHCHK] {url} → ERROR: {e}")

def continuous_healthcheck(real_domain: str, app_port: int, interval: int = 60):
    """
    Loop forever, calling self_test_once every `interval` seconds.
    """
    while True:
        self_test_once(real_domain, app_port)
        time.sleep(interval)


# ─── 13) MAIN ──────────────────────────────────────────────────────────────────
def main():
    # 13.1) Load (or create) config, then chdir to serve_path
    cfg = load_config()
    if not os.path.exists(CONFIG_PATH):
        cfg["serve_path"] = input(f"Serve path [{cfg['serve_path']}]: ") or cfg["serve_path"]
        save_config(cfg)
    os.chdir(cfg["serve_path"])

    # 13.2) Load domain.conf → either 'mode':'dev' or 'mode':'prod'
    nc = load_domain_conf()
    mode = nc.get("mode", "dev")

    # 13.3) Pick a free app_port (start at 3000, increment if busy)
    app_port = BASE_APP_PORT
    while port_in_use(app_port):
        print(f"⚠ Port {app_port} in use; trying {app_port+1} …")
        app_port += 1
        if app_port > BASE_APP_PORT + 20:
            print("⚠ Could not find a free port in the 3000–3020 range. Exiting.")
            sys.exit(1)
    if app_port != BASE_APP_PORT:
        print(f"ℹ Will use port {app_port} for your Node app (3000 was busy).")

    # 13.4) Launch Node app on chosen port (plain HTTP)
    proc = None
    if os.path.exists("package.json") and os.path.exists("server.js") and shutil.which("node"):
        print("⏳ Installing npm dependencies…")
        subprocess.check_call(["npm", "install"], cwd=cfg["serve_path"])
        print(f"⏳ Starting Node app on port {app_port} …")
        user_log = os.path.join(cfg["serve_path"], "node.log")
        try:
            log_file = open(user_log, "a")
        except:
            log_file = subprocess.DEVNULL

        proc = subprocess.Popen(
            ["npm", "run", "start"],
            cwd=cfg["serve_path"],
            stdout=log_file,
            stderr=log_file,
            env={**os.environ, "PORT": str(app_port)}
        )
        # Give Node a moment to spin up
        time.sleep(2)
        print(f"✅ Node is listening on http://0.0.0.0:{app_port}")
    else:
        print("⚠ No `package.json`/`server.js` found or `node` missing; skipping Node launch.")

    # 13.5) Set up SSH key + fingerprint (needed in both DEV & PROD)
    fingerprint = ensure_ssh_key()
    fingerprint_value = f"SHA256:{fingerprint}"

    # 13.6) If PRODUCTION: update Cloudflare DNS first
    real_domain = None
    if mode == "prod":
        zone = nc["zone_name"]
        host = nc["host"]
        real_domain = f"{host}.{zone}"
        print(f"⏳ Updating Cloudflare DNS for {real_domain} (CNAME→serveo.net, TXT→{fingerprint_value}) …")
        update_cloudflare(nc, "serveo.net", fingerprint_value)

        # Wait ~60 seconds for DNS to propagate
        print(f"\n⏳ Waiting 60 seconds for DNS to propagate … (Cloudflare TTL is {nc.get('ttl', DEFAULT_TTL)} s)")
        time.sleep(60)

    # 13.7) Establish Serveo tunnel (10s timeout) 
    # DEV: no real_domain passed → random ephemeral. 
    # PROD: pass real_domain → bind custom domain
    print("⏳ Starting Serveo tunnel (10s timeout)…")
    tunnel_host = start_serveo_tunnel(timeout=10, app_port=app_port, real_domain=real_domain)

    if not tunnel_host:
        print("⚠ Serveo tunnel failed or timed out. Exiting.")
        if proc:
            proc.terminate()
        sys.exit(1)

    # 13.8) If PROD: schedule a re-update of Cloudflare in 5 minutes 
    if mode == "prod":
        threading.Thread(
            target=lambda: (time.sleep(300), update_cloudflare(nc, "serveo.net", fingerprint_value)),
            daemon=True
        ).start()

    # 13.9) Generate TLS certificate for local dev testing
    cert_file = os.path.join(cfg["serve_path"], "cert.pem")
    key_file  = os.path.join(cfg["serve_path"], "key.pem")
    # In DEV mode, real_domain is None → pass a dummy; we only care about SAN for random tunnel
    san_domain = tunnel_host if not real_domain else real_domain
    generate_cert(cert_file, key_file, san_domain, tunnel_host)

    # 13.10) Start local dev HTTPS on 9443 → Node
    start_local_https(cert_file, key_file, app_port)

    # 13.11) Print final banner
    lan_ip = get_lan_ip()
    final_domain = san_domain if mode=="prod" else tunnel_host
    print_banner(lan_ip, final_domain, app_port)
    print(f"✅ {'Development' if mode=='dev' else 'Production'} will be accessible at: https://{final_domain} (via Serveo → {tunnel_host})\n")
    print("⚠ All services started. Press Ctrl+C to terminate.")

    # 13.12) Spawn health-check thread
    health_thread = threading.Thread(
        target=lambda: continuous_healthcheck(final_domain, app_port, interval=60),
        daemon=True
    )
    health_thread.start()

    # 13.13) Block main thread until Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nReceived Ctrl+C; shutting down…")
        if proc:
            proc.terminate()
        sys.exit(0)


if __name__ == "__main__":
    bootstrap_and_run()
