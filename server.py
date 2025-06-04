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
import signal

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

# Health-check interval (seconds)
HEALTH_INTERVAL = 60

# How many consecutive failures before restarting tunnel
MAX_FAILURES = 5

# Global handles so we can terminate on Ctrl+C
node_proc   = None
tunnel_proc = None
tunnel_host = None

# Lock to synchronize tunnel restarts
tunnel_lock = threading.Lock()

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
    print("   1) DEV (no Cloudflare, just random tunnel subdomain)")
    print("   2) PRODUCTION (Cloudflare + custom subdomain)")
    choice = input("Enter 1 or 2: ").strip()
    if choice not in ("1", "2"):
        print("Invalid choice—please run again and choose 1 or 2.")
        sys.exit(1)

    if choice == "1":
        # DEV mode: no DNS changes needed
        conf = {"mode": "dev"}
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
      • <tunnel_domain> (e.g. abc123.lhr.gg)
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


# ─── 10) GENERIC TUNNEL LAUNCHER ─────────────────────────────────────────────────
def _spawn_and_capture(cmd, regex_list, timeout):
    """
    Run subprocess cmd, capture stdout/err lines until one of regex_list matches.
    Returns (matched hostname, process) or (None, None) on failure/timeout.
    """
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid
        )
    except Exception:
        return None, None

    host = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([p.stdout], [], [], 0.5)
        if ready:
            line = p.stdout.readline()
            if not line:
                continue
            for pattern in regex_list:
                m = pattern.search(line)
                if m:
                    host = m.group(1).strip()
                    break
            if host:
                break

    if not host:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except:
            pass
        return None, None

    return host, p


def clean_label(s: str) -> str:
    """
    Replace any non-alphanumeric with '-', collapse multiple '-' into one,
    strip leading/trailing '-'.
    E.g. "hypermindlabs.org" → "hypermindlabs-org"
    """
    tmp = re.sub(r'[^A-Za-z0-9]', '-', s)
    tmp = re.sub(r'-+', '-', tmp)
    return tmp.strip('-')


def start_tunnel_chain(timeout: int, app_port: int, host: str = None, zone_name: str = None):
    """
    Try LocalTunnel first (with custom subdomain if host+zone_name present), then fall back:
      1) LocalTunnel (Node.js 'lt')
      2) Serveo (SSH)
      3) localhost.run (SSH)
      4) nglocalhost.com (SSH)
      5) Staqlab Tunnel (CLI)
      6) Cloudflare TryCloudflare (cloudflared)

    If host and zone_name are provided, we clean both (strip punctuation → dashes)
    and form desired_sub = "<host_clean>-<zone_clean>". We attempt that first;
    if unavailable, we then try a random LT host before falling back to other services.

    Returns (matched_hostname, process) or (None, None) on complete failure.
    """
    patterns = {
        "localtunnel":   re.compile(r"your url is:\s+https?://([\w\-.]+(?:\.loca\.lt|\.localtunnel\.me))", re.IGNORECASE),
        "serveo":        re.compile(r"Forwarding\s+HTTP\s+traffic\s+from\s+https?://([\w\-.]+)"),
        "localhost_run": re.compile(r"Forwarding\s+HTTP\s+traffic\s+from\s+https?://([\w\-.]+\.lhr\.gg|[\w\-.]+\.localhost\.run)"),
        "nglocal":       re.compile(r"Forwarding\s+HTTP\s+traffic\s+from\s+https?://([\w\-.]+\.nglocalhost\.com)"),
        "staqlab":       re.compile(r"(?:https?://)?([\w\-.]+\.staqlab\.net)"),
        "cloudflare":    re.compile(r"https?://([\w\-.]+\.trycloudflare\.com)")
    }

    # ─────────────────────────────
    # 1) LocalTunnel (custom then random)
    # ─────────────────────────────
    if shutil.which("lt"):
        desired_sub = None
        if host and zone_name:
            print(f"→ domain.conf provided: host='{host}', zone_name='{zone_name}'")
            zone_base  = zone_name.split('.')[0]
            host_clean = clean_label(host)
            zone_clean = clean_label(zone_base)
            desired_sub = f"{host_clean}-{zone_clean}"
            print(f"→ Attempting LocalTunnel with custom subdomain: '{desired_sub}'")
            cmd = ["lt", "--port", str(app_port), "--subdomain", desired_sub]
        else:
            print("→ No host+zone_name available → using random LocalTunnel subdomain")
            cmd = ["lt", "--port", str(app_port)]

        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid
        )
        tunnel_proc_local = p

        host_assigned = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([p.stdout], [], [], 0.5)
            if ready:
                line = p.stdout.readline()
                if not line:
                    continue

                # If our desired_sub is taken, LT prints “Subdomain <…> is not available”
                if desired_sub and "Subdomain" in line and ("not available" in line or "already in use" in line):
                    print(f"⚠ LocalTunnel: '{desired_sub}' unavailable → {line.strip()}")
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                    host_assigned = None
                    break

                # Look for "your url is: https://<host>"
                m = patterns["localtunnel"].search(line)
                if m:
                    host_assigned = m.group(1).strip()
                    break

        if host_assigned:
            if desired_sub:
                if host_assigned.startswith(desired_sub + "."):
                    print(f"✅ LocalTunnel (custom) established: https://{host_assigned}")
                    return host_assigned, tunnel_proc_local
                else:
                    print(f"⚠ LocalTunnel assigned random host '{host_assigned}' instead of '{desired_sub}'")
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                    # fall through to random logic below
            else:
                print(f"✅ LocalTunnel established: https://{host_assigned}")
                return host_assigned, tunnel_proc_local

        # If custom failed or yielded random
        if desired_sub:
            print("→ Now trying LocalTunnel with a truly random subdomain…")
            p2 = subprocess.Popen(
                ["lt", "--port", str(app_port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid
            )
            tunnel_proc_local2 = p2

            host_random = None
            deadline2 = time.time() + timeout
            while time.time() < deadline2:
                ready2, _, _ = select.select([p2.stdout], [], [], 0.5)
                if ready2:
                    line2 = p2.stdout.readline()
                    if not line2:
                        continue
                    m2 = patterns["localtunnel"].search(line2)
                    if m2:
                        host_random = m2.group(1).strip()
                        break

            if host_random:
                print(f"✅ LocalTunnel (random) established: https://{host_random}")
                return host_random, tunnel_proc_local2
            else:
                try:
                    os.killpg(os.getpgid(p2.pid), signal.SIGTERM)
                except:
                    pass

        print("⚠ LocalTunnel failed; trying next service…")

    # ─────────────────────────────
    # 2) Serveo (SSH)
    # ─────────────────────────────
    if shutil.which("ssh"):
        if host and zone_name:
            desired = f"{host}.{zone_name}"
            print(f"→ Attempting Serveo with custom host '{desired}'")
            forward = f"{desired}:80:localhost:{app_port}"
        else:
            print("→ Attempting Serveo with random host")
            forward = f"80:localhost:{app_port}"
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ExitOnForwardFailure=yes",
            "-R", forward,
            "serveo.net"
        ]
        service_host, proc = _spawn_and_capture(cmd, [patterns["serveo"]], timeout)
        if service_host:
            print(f"✅ Serveo tunnel established: https://{service_host}")
            return service_host, proc
        print("⚠ Serveo failed; trying next service…")

    # ─────────────────────────────
    # 3) localhost.run (SSH)
    # ─────────────────────────────
    if shutil.which("ssh"):
        print("→ Attempting localhost.run (random)")
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ExitOnForwardFailure=yes",
            "-R", f"80:localhost:{app_port}",
            "localhost.run"
        ]
        service_host, proc = _spawn_and_capture(cmd, [patterns["localhost_run"]], timeout)
        if service_host:
            print(f"✅ localhost.run tunnel established: https://{service_host}")
            return service_host, proc
        print("⚠ localhost.run failed; trying next service…")

    # ─────────────────────────────
    # 4) nglocalhost.com (SSH)
    # ─────────────────────────────
    if shutil.which("ssh"):
        print("→ Attempting nglocalhost.com (random)")
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ExitOnForwardFailure=yes",
            "-R", f"80:localhost:{app_port}",
            "nglocalhost.com"
        ]
        service_host, proc = _spawn_and_capture(cmd, [patterns["nglocal"]], timeout)
        if service_host:
            print(f"✅ nglocalhost tunnel established: https://{service_host}")
            return service_host, proc
        print("⚠ nglocalhost failed; trying next service…")

    # ─────────────────────────────
    # 5) Staqlab Tunnel (CLI)
    # ─────────────────────────────
    if shutil.which("staqlab-tunnel"):
        if host:
            print(f"→ Attempting Staqlab Tunnel with custom hostname '{host}'")
            cmd = ["staqlab-tunnel", str(app_port), f"hostname={host}"]
        else:
            print("→ Attempting Staqlab Tunnel (random)")
            cmd = ["staqlab-tunnel", str(app_port)]
        service_host, proc = _spawn_and_capture(cmd, [patterns["staqlab"]], timeout)
        if service_host:
            print(f"✅ Staqlab tunnel established: https://{service_host}")
            return service_host, proc
        print("⚠ Staqlab failed; trying next service…")

    # ─────────────────────────────
    # 6) Cloudflare TryCloudflare (cloudflared)
    # ─────────────────────────────
    if shutil.which("cloudflared"):
        print("→ Attempting Cloudflare TryCloudflare (random)")
        cmd = ["cloudflared", "tunnel", "--url", f"http://localhost:{app_port}", "--no-autoupdate"]
        service_host, proc = _spawn_and_capture(cmd, [patterns["cloudflare"]], timeout)
        if service_host:
            print(f"✅ Cloudflare tunnel established: https://{service_host}")
            return service_host, proc
        print("⚠ Cloudflare trycloudflare failed; no more fallbacks available.")

    return None, None


# ─── 11) UPDATE CLOUDFLARE CNAME + TXT ───────────────────────────────────────────
def update_cloudflare(conf: dict, cname_target: str, txt_value: str):
    """
    Use Cloudflare’s API to set/update two DNS records in the specified zone:
      1) CNAME record at <host>.<zone_name> → cname_target
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

    # Upsert CNAME: <host>.<zone_name> → cname_target (proxied=False)
    upsert_record("CNAME", full_name, cname_target, proxied=False)

    # Upsert TXT: _serveo-authkey.<host>.<zone_name> → SHA256:<fingerprint>
    upsert_record("TXT", txt_record_name, txt_value, proxied=False)


# ─── 12) HEARTBEAT / TUNNEL MONITOR ─────────────────────────────────────────────
def tunnel_health_monitor(check_url: str, app_port: int, conf: dict):
    """
    Periodically check the tunnel URL. If it fails consecutively MAX_FAILURES times,
    restart the tunnel, update DNS if in prod, regenerate certs, and resume checks.
    """
    global tunnel_proc, tunnel_host

    failures = 0
    while True:
        try:
            resp = urllib.request.urlopen(check_url, timeout=5)
            status = getattr(resp, 'status', None) or resp.getcode()
            if status == 200:
                failures = 0
                print(f"✅ Tunnel heartbeat OK: {check_url}")
            else:
                failures += 1
                print(f"⚠ Tunnel heartbeat HTTP {status} ({failures}/{MAX_FAILURES})")
        except Exception as e:
            failures += 1
            print(f"⚠ Tunnel heartbeat failed ({failures}/{MAX_FAILURES}): {e}")

        if failures >= MAX_FAILURES:
            print(f"‼️  Tunnel unreachable {MAX_FAILURES}×; restarting tunnel…")
            with tunnel_lock:
                # Terminate old tunnel
                if tunnel_proc:
                    try:
                        os.killpg(os.getpgid(tunnel_proc.pid), signal.SIGTERM)
                    except:
                        pass

                # Restart tunnel
                new_host, new_proc = start_tunnel_chain(
                    timeout=10,
                    app_port=app_port,
                    host=conf.get("host"),
                    zone_name=conf.get("zone_name")
                )
                if not new_host:
                    print("⚠ Failed to re-establish tunnel; will retry in next cycle.")
                    failures = 0
                    time.sleep(HEALTH_INTERVAL)
                    continue

                tunnel_host = new_host
                tunnel_proc = new_proc
                print(f"🔄 New tunnel established: https://{tunnel_host}")

                # Update DNS if in prod
                if conf.get("mode") == "prod" and conf.get("host") and conf.get("zone_name"):
                    real_domain = f"{conf['host']}.{conf['zone_name']}"
                    fingerprint = ensure_ssh_key()
                    fingerprint_value = f"SHA256:{fingerprint}"
                    print(f"\n⏳ Updating Cloudflare DNS for {real_domain} (CNAME→{tunnel_host}, TXT→{fingerprint_value}) …")
                    update_cloudflare(conf, tunnel_host, fingerprint_value)

                # Regenerate cert
                cert_file = os.path.join(conf.get("serve_path", SCRIPT_DIR), "cert.pem")
                key_file  = os.path.join(conf.get("serve_path", SCRIPT_DIR), "key.pem")
                san_domain = real_domain if conf.get("host") and conf.get("zone_name") else tunnel_host
                generate_cert(cert_file, key_file, san_domain, tunnel_host)

                # Update check_url
                check_url = f"https://{tunnel_host}/"

                failures = 0
                print(f"✅ Tunnel rotated successfully: {check_url}")

        time.sleep(HEALTH_INTERVAL)


# ─── 13) SIGNAL HANDLER FOR GRACEFUL SHUTDOWN ───────────────────────────────────
def handle_sigint(signum, frame):
    global node_proc, tunnel_proc
    print("\nReceived Ctrl+C; shutting down…")
    if node_proc:
        try:
            os.killpg(os.getpgid(node_proc.pid), signal.SIGTERM)
        except:
            pass
    if tunnel_proc:
        try:
            os.killpg(os.getpgid(tunnel_proc.pid), signal.SIGTERM)
        except:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)


# ─── 14) MAIN ──────────────────────────────────────────────────────────────────
def main():
    global node_proc, tunnel_proc, tunnel_host

    # 14.1) Load (or create) config, then chdir to serve_path
    cfg = load_config()
    if not os.path.exists(CONFIG_PATH):
        cfg["serve_path"] = input(f"Serve path [{cfg['serve_path']}]: ") or cfg["serve_path"]
        save_config(cfg)
    os.chdir(cfg["serve_path"])

    # 14.2) Load domain.conf → attempt to extract host and zone_name regardless of mode
    nc = load_domain_conf()
    host      = nc.get("host")
    zone_name = nc.get("zone_name")
    mode      = nc.get("mode", "dev")

    # Debug: show exactly what loaded
    print(f"→ Loaded domain.conf → mode='{mode}', host='{host}', zone_name='{zone_name}'")

    # 14.3) Pick a free app_port (start at 3000, increment if busy)
    app_port = BASE_APP_PORT
    while port_in_use(app_port):
        print(f"⚠ Port {app_port} in use; trying {app_port+1} …")
        app_port += 1
        if app_port > BASE_APP_PORT + 20:
            print("⚠ Could not find a free port in the 3000–3020 range. Exiting.")
            sys.exit(1)
    if app_port != BASE_APP_PORT:
        print(f"ℹ Will use port {app_port} for your Node app (3000 was busy).")

    # 14.4) Launch Node app on chosen port (plain HTTP)
    if os.path.exists("package.json") and os.path.exists("server.js") and shutil.which("node"):
        print("⏳ Installing npm dependencies…")
        subprocess.check_call(["npm", "install"], cwd=cfg["serve_path"])
        print(f"⏳ Starting Node app on port {app_port} …")
        user_log = os.path.join(cfg["serve_path"], "node.log")
        try:
            log_file = open(user_log, "a")
        except:
            log_file = subprocess.DEVNULL

        # Launch Node in its own process group
        node_proc = subprocess.Popen(
            ["npm", "run", "start"],
            cwd=cfg["serve_path"],
            stdout=log_file,
            stderr=log_file,
            env={**os.environ, "PORT": str(app_port)},
            preexec_fn=os.setsid
        )
        # Give Node a moment to spin up
        time.sleep(2)
        print(f"✅ Node is listening on http://0.0.0.0:{app_port}")
    else:
        print("⚠ No `package.json`/`server.js` found or `node` missing; skipping Node launch.")

    # 14.5) Set up SSH key + fingerprint (needed in both DEV & PROD)
    fingerprint = ensure_ssh_key()
    fingerprint_value = f"SHA256:{fingerprint}"

    # 14.6) If zone_name+host exist, we’ll do DNS update after Serveo
    real_domain = None
    if host and zone_name:
        real_domain = f"{host}.{zone_name}"
        print(f"\n⏳ Will establish Serveo tunnel (using host+zone_name) before updating Cloudflare DNS…\n")
    else:
        print("\n⏳ Establishing Serveo tunnel without custom host/zone_name…\n")

    # 14.7) Establish Serveo first (10s timeout)
    print("⏳ Starting tunnel chain (Serveo first, 10s timeout)…")
    serveo_patterns = [re.compile(r"Forwarding\s+HTTP\s+traffic\s+from\s+https?://([\w\-.]+)")]
    if shutil.which("ssh"):
        if host and zone_name:
            desired = f"{host}.{zone_name}"
            print(f"→ Attempting Serveo with custom host '{desired}'")
            forward = f"{desired}:80:localhost:{app_port}"
        else:
            print("→ Attempting Serveo with random host")
            forward = f"80:localhost:{app_port}"
        serveo_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ExitOnForwardFailure=yes",
            "-R", forward,
            "serveo.net"
        ]
        p = subprocess.Popen(
            serveo_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid
        )
        serveo_host = None
        deadline = time.time() + 10
        while time.time() < deadline:
            ready, _, _ = select.select([p.stdout], [], [], 0.5)
            if ready:
                line = p.stdout.readline()
                if not line:
                    continue
                m = serveo_patterns[0].search(line)
                if m:
                    serveo_host = m.group(1).strip()
                    break
        if not serveo_host:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except:
                pass
        else:
            print(f"✅ Serveo tunnel established: https://{serveo_host}")
            tunnel_host = serveo_host
            tunnel_proc = p
    else:
        serveo_host = None

    # 14.8) If Serveo succeeded and in PROD, update Cloudflare CNAME→serveo.net & TXT
    if serveo_host and host and zone_name:
        print(f"\n⏳ Updating Cloudflare DNS for {real_domain} (CNAME→serveo.net, TXT→{fingerprint_value}) …")
        update_cloudflare(nc, "serveo.net", fingerprint_value)
        def reupdate_cf():
            time.sleep(300)
            update_cloudflare(nc, "serveo.net", fingerprint_value)
        threading.Thread(target=reupdate_cf, daemon=True).start()
    elif host and zone_name:
        # Serveo failed in prod
        print("⚠ Serveo failed; skipping Cloudflare update.")

    # 14.9) After Serveo (regardless of success), spin up LocalTunnel & fallbacks in parallel using custom subdomain
    print("\n⏳ Starting LocalTunnel & fallbacks (10s timeout)…\n")
    def launch_tunnel_chain():
        global tunnel_host, tunnel_proc
        lt_host, lt_proc = start_tunnel_chain(
            timeout=10,
            app_port=app_port,
            host=host,
            zone_name=zone_name
        )
        if lt_host:
            print(f"✅ LocalTunnel/fallback tunnel active: https://{lt_host}")
            # If we didn’t get a Serveo host, use LT as tunnel_host
            if not tunnel_host:
                tunnel_host = lt_host
                tunnel_proc = lt_proc
        else:
            print("⚠ All LocalTunnel-based tunnels failed or timed out.")

    threading.Thread(target=launch_tunnel_chain, daemon=True).start()

    # 14.10) Generate TLS certificate for local dev testing (include real_domain or tunnel_host as SANs)
    cert_file = os.path.join(cfg["serve_path"], "cert.pem")
    key_file  = os.path.join(cfg["serve_path"], "key.pem")
    san_primary = real_domain if real_domain else tunnel_host if tunnel_host else "localhost"
    san_secondary = tunnel_host if real_domain and tunnel_host else san_primary
    generate_cert(cert_file, key_file, san_primary, san_secondary)

    # 14.11) Start local dev HTTPS on 9443 → Node
    start_local_https(cert_file, key_file, app_port)

    # 14.12) Print final banner
    lan_ip = get_lan_ip()
    final_domain = real_domain if real_domain else tunnel_host if tunnel_host else "localhost"
    print_banner(lan_ip, final_domain, app_port)
    print(f"✅ {'Development' if mode=='dev' else 'Production'} is accessible at: https://{final_domain} (via tunnel → {tunnel_host})\n")
    print("⚠ All services started. Press Ctrl+C to terminate.")

    # 14.13) Start tunnel-health-monitor thread
    if tunnel_host:
        check_url = f"https://{tunnel_host}/"
        monitor_thread = threading.Thread(
            target=lambda: tunnel_health_monitor(check_url, app_port, nc),
            daemon=True
        )
        monitor_thread.start()

    # 14.14) Block main thread until Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    bootstrap_and_run()
