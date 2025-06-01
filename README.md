# Serveo Local Development and Production Forwarder

A step-by-step guide to get your Node.js app exposed locally (HTTPS) and to the world via Serveo.  This README covers both **DEV** mode (no DNS changes, random `*.serveo.net` host) and **PRODUCTION** mode (Cloudflare + custom subdomain).  Follow the instructions carefully to avoid the dreaded 502 error.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Repository Layout](#repository-layout)
3. [Installing Dependencies](#installing-dependencies)
4. [Running in DEV Mode](#running-in-dev-mode)
5. [Running in PRODUCTION Mode (Cloudflare + Custom Subdomain)](#running-in-production-mode-cloudflare--custom-subdomain)

   1. [Creating a Cloudflare API Token](#creating-a-cloudflare-api-token)
   2. [Invoking the Script in Production Mode](#invoking-the-script-in-production-mode)
   3. [DNS Records Automatically Set by the Script](#dns-records-automatically-set-by-the-script)
   4. [Verifying Propagation & Testing](#verifying-propagation--testing)
6. [How It Works: Key Points](#how-it-works-key-points)

   1. [SSH Key & Fingerprint](#ssh-key--fingerprint)
   2. [TXT Record Naming](#txt-record-naming)
   3. [CNAME Target for Custom Domain](#cname-target-for-custom-domain)
   4. [Custom-Domain SSH Command](#custom-domain-ssh-command)
   5. [SSL Certificates + Local HTTPS](#ssl-certificates--local-https)
7. [Troubleshooting](#troubleshooting)

   1. [502 Errors from Cloudflare](#502-errors-from-cloudflare)
   2. [“Unable to find active zone” Errors](#unable-to-find-active-zone-errors)
   3. [SSL Certificate Issues](#ssl-certificate-issues)
8. [Full Script Listing](#full-script-listing)
9. [Appendix: Useful Links](#appendix-useful-links)

---

## Prerequisites

Before you begin, make sure you have:

1. **Node.js** (v14.x or higher recommended)

   * Confirm by running:

     ```bash
     node --version
     npm --version
     ```
   * If you don’t have Node, download & install from [nodejs.org](https://nodejs.org/).

2. **Python 3** (3.7+), plus `pip`

   * Confirm by running:

     ```bash
     python3 --version
     pip3 --version
     ```
   * If you don’t have Python 3 installed, install via your OS package manager or from [python.org](https://www.python.org/).

3. **ssh** (OpenSSH client)

   * Confirm:

     ```bash
     ssh -V
     ```
   * If missing, install your OS’s OpenSSH client package (e.g. `sudo apt install openssh-client` on Ubuntu).

4. A **Cloudflare account** (for PRODUCTION mode) and access to the zone you intend to use (e.g. `hypermindlabs.org`).

   * You will generate an **API Token** with “Edit zone DNS” permissions (see below).

5. A **Namecheap** or other DNS registrar is *not needed* in PRODUCTION mode—everything is handled via Cloudflare.  (If you were using Namecheap’s API previously, drop all those records—our script has moved to Cloudflare exclusively.)

6. A working **Node.js project** in the same folder (must contain `package.json` and `server.js`).  The script expects you have a typical Node app that listens on `process.env.PORT` (default 3000).

---

## Repository Layout

Assume the repo looks like this:

```
/my-app
  ├── server.js
  ├── package.json
  ├── server.py          ← our Python orchestration script
  ├── config.json        ← auto‐generated (stores “serve_path”)
  ├── domain.conf        ← auto‐generated (stores dev/prod config)
  └── venv/              ← virtualenv folder (Python dependencies)
```

* **`server.py`** is the orchestration script you’ll run.
* **`server.js`** is your Node app entry (as usual).
* **`domain.conf`** and **`config.json`** are created/updated by `server.py`.

---

## Installing Dependencies

1. **Clone or copy** this repository (your Node app + `server.py`) to your local machine.

   ```bash
   git clone https://github.com/your‐repo/my-app.git
   cd my-app
   ```

2. **Ensure your Node app files** (`package.json` and `server.js`) are present in this directory.

3. **Make `server.py` executable** (if needed):

   ```bash
   chmod +x server.py
   ```

4. **Run `server.py`.** On its first execution, it will create a Python virtual environment and install the required Python packages (`cryptography` and `requests`).

   ```bash
   ./server.py
   ```

   You’ll see output like:

   ```
   Creating virtualenv… |
   Installing dependencies… |
   ```

   After venv is ready, the script re‐executes inside the virtual environment.

   * If you ever want to re‐install or upgrade Python deps, delete the `venv/` folder and re‐run `server.py`.

---

## Running in DEV Mode

Use **DEV mode** when you want:

* A quick HTTPS endpoint on `localhost:9443` (certificate covers `localhost`, your LAN IP, and the ephemeral Serveo host).
* A random subdomain like `abcdef1234.serveo.net` that tunnels to your local Node.
* No DNS changes, no Cloudflare, no custom domain.

### Steps

1. Run the script:

   ```bash
   ./server.py
   ```

2. When prompted, choose:

   ```
   ⚠  Do you want to run in DEV mode or PRODUCTION mode?
      1) DEV (no Cloudflare, just random Serveo subdomain)
      2) PRODUCTION (Cloudflare + custom subdomain)
   Enter 1 or 2: 1
   ```

3. The script will:

   * Find a free port (3000, 3001, …) for your Node server.
   * Install npm dependencies (`npm install`).
   * Launch `npm run start` (expects your `package.json` to have a “start” script; sets `PORT=<chosen_port>`).
   * Launch an SSH tunnel via Serveo:

     ```
     ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -R 80:localhost:<port> serveo.net
     ```

     and parse Serveo’s output to get something like:

     ```
     Forwarding HTTP traffic from https://abcdef1234.serveo.net to localhost:3000
     ```
   * Generate a self‐signed (or mkcert) certificate covering:

     * `localhost`
     * `<your_lan_ip>`
     * the random `abcdef1234.serveo.net`
     * `127.0.0.1`
   * Start a local HTTPS reverse‐proxy on port **9443** that forwards to your Node on `<port>`.
   * Print a banner:

     ```
     ╔═══════════════════════════════════════════╗
     ║  Node (HTTP)  → http://127.0.0.1:<port>    ║
     ║  Local Dev    → https://localhost:9443    ║
     ║  LAN Dev      → https://<LAN_IP>:9443     ║
     ║  Production   → https://abcdef1234.serveo.net ║
     ╚═══════════════════════════════════════════╝

     ✅ Development will be accessible at: https://abcdef1234.serveo.net (via Serveo)
     ```

4. **Test Locally**:

   * `curl -I http://127.0.0.1:<port>/` → should return `200`.
   * `curl -k -I https://localhost:9443/` → should return `200` (ignore cert warning or add `-k`).
   * `curl -k -I https://<LAN_IP>:9443/` → should return `200`.
   * `curl -I https://abcdef1234.serveo.net/` → should return `200`.  (No 502s, because Serveo expects the ephemeral host.)

5. **When you’re done**, press **Ctrl+C** in the terminal. That will kill the SSH tunnel, Node process, and the local HTTPS proxy.

---

## Running in PRODUCTION Mode (Cloudflare + Custom Subdomain)

Use **PRODUCTION mode** when you want to bind your own subdomain—for example:

```
chat.hypermindlabs.org → tunnels to your local Node via Serveo
```

All DNS changes are done automatically via the Cloudflare API.  You only have to supply:

1. A Cloudflare API Token with “Edit zone DNS” permissions.
2. Your Cloudflare **Zone Name** (e.g. `hypermindlabs.org`)
3. A subdomain (e.g. `chat`)
4. TTL (default 300 seconds).

The script will then:

* Create two DNS records via Cloudflare’s API:

  1. **CNAME** `chat.hypermindlabs.org → serveo.net` (proxied = OFF)
  2. **TXT** `_serveo-authkey.chat.hypermindlabs.org → "SHA256:<your-ssh-fingerprint>"` (proxied = OFF)
* Wait \~60 seconds for propagation.
* Run:

  ```
  ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
      -R chat.hypermindlabs.org:80:localhost:<port> serveo.net
  ```

  That binds `chat.hypermindlabs.org` to your local Node.
* Generate a multi-SAN certificate covering:

  * `localhost`
  * your LAN IP (e.g. `192.168.1.42`)
  * `chat.hypermindlabs.org`
  * the ephemeral Serveo hostname (if any)
  * `127.0.0.1`
* Start a local HTTPS reverse-proxy on port **9443** (forwarding to Node).
* Print a banner with all endpoints.

### 5.1 Creating a Cloudflare API Token

1. **Log in** to your Cloudflare dashboard:
   [https://dash.cloudflare.com](https://dash.cloudflare.com)

2. In the top menu, click **“Profile”** (your user icon) → **API Tokens**.

   * Alternatively, go directly to:
     [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)

3. Click **“Create Token”**.

4. **Choose a Template**:

   * Select **“Edit zone DNS”** (this will grant just enough permissions to list zones and create/update DNS records).
   * You can also create a custom token with exactly these permissions:

     * **Zone → DNS → Edit**
     * **Account → Read → Zones**

5. In **“Zone Resources”**, set “Include” to “Specific zone” and choose your domain (e.g. `hypermindlabs.org`).

   * This ensures the token only works for that one zone.

6. Click **“Continue to summary”**, review, and **“Create Token”**.

7. Copy the newly minted token.  **Store it safely**, because you’ll need it when the script prompts:

   ```
   Cloudflare API Token: <paste-token-here>
   ```

---

### 5.2 Invoking the Script in Production Mode

1. **Run** the orchestration script:

   ```bash
   ./server.py
   ```

2. When prompted:

   ```
   ⚠  Do you want to run in DEV mode or PRODUCTION mode?
      1) DEV (no Cloudflare, just random Serveo subdomain)
      2) PRODUCTION (Cloudflare + custom subdomain)
   Enter 1 or 2: 2
   ```

3. Then provide:

   * **Cloudflare API Token**: (the token you just created)
   * **Cloudflare Zone Name**: e.g. `hypermindlabs.org`
   * **Subdomain**: e.g. `chat`  (that becomes `chat.hypermindlabs.org`)
   * **DNS TTL**: default `300` (press Enter to accept)

   Example:

   ```
   Cloudflare API Token     : R9V9XWF-aIsWacXw0YYh2IsntIG-V_x1w5UqL_Ad
   Cloudflare Zone Name     : hypermindlabs.org
   Subdomain (e.g. chat)    : chat
   DNS TTL (secs) [300]: 300
   ```

4. The script will validate your zone name by calling:

   ```
   GET https://api.cloudflare.com/client/v4/zones?name=hypermindlabs.org&status=active
   ```

   If it returns a valid zone, you’ll see:

   ```
   ✅ Found zone_id: abcdef1234567890abcdef1234567890
   ```

5. The script calls the Cloudflare API to create/update:

   * **CNAME** `chat.hypermindlabs.org → serveo.net`
   * **TXT** `_serveo-authkey.chat.hypermindlabs.org → "SHA256:<fingerprint>"`

   You’ll see output like:

   ```
   [Cloudflare] Created CNAME record chat.hypermindlabs.org → serveo.net  (TTL=300)
   [Cloudflare] Created TXT record _serveo-authkey.chat.hypermindlabs.org → SHA256:QpVnrJXD96qfx8KxduKxt2i9mB3JnVbK8GVoFlk7Ybo  (TTL=300)
   ```

6. **Wait \~60 seconds** for DNS to propagate.  The script shows:

   ```
   ⏳ Waiting 60 seconds for DNS to propagate … (Cloudflare TTL is 300 s)
   ```

7. Next, the script runs:

   ```
   ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
       -R chat.hypermindlabs.org:80:localhost:<port> serveo.net
   ```

   You should see Serveo’s confirmation:

   ```
   ✅ Serveo tunnel established: https://chat.hypermindlabs.org
   ```

8. Finally, it generates a certificate (self‐signed or via `mkcert`) valid for:

   ```
   “localhost”, “<LAN_IP>”, “chat.hypermindlabs.org”, “<ephemeral.serveo.net>”, “127.0.0.1”
   ```

   and starts the local HTTPS proxy on port **9443**.

9. **Banner Example**:

   ```
   ╔═══════════════════════════════════════════════════╗
   ║  Node (HTTP)  → http://127.0.0.1:3015             ║
   ║  Local Dev    → https://localhost:9443            ║
   ║  LAN Dev      → https://192.168.1.42:9443         ║
   ║  Production   → https://chat.hypermindlabs.org    ║
   ╚═══════════════════════════════════════════════════╝

   ✅ Production will be accessible at: https://chat.hypermindlabs.org (via Serveo → chat.hypermindlabs.org)

   ⚠ All services started. Press Ctrl+C to terminate.
   ```

---

### 5.3 DNS Records Automatically Set by the Script

Once the script finishes (in PRODUCTION mode), you can log in to your Cloudflare dashboard → DNS for `hypermindlabs.org` and verify that you have exactly these records (CNAME & TXT), **both set to “DNS only”** (grey cloud):

| Type  | Name                                     | Content                | TTL | Proxy |
| ----- | ---------------------------------------- | ---------------------- | --- | ----- |
| CNAME | `chat.hypermindlabs.org`                 | `serveo.net`           | 300 | Off   |
| TXT   | `_serveo-authkey.chat.hypermindlabs.org` | `SHA256:<fingerprint>` | 300 | Off   |

* **Why “DNS only”?**

  * If you set the CNAME to **“Proxied (orange cloud)”** (Cloudflare’s CDN/WAF), Cloudflare will forward HTTP requests with `Host: chat.hypermindlabs.org` to some Cloudflare IP. Cloudflare then tries to talk to the origin (which is behind the CNAME → `serveo.net`), but it sends the wrong `Host:` header to Serveo (still `chat.hypermindlabs.org`). Serveo expects to only see `Host: chat.hypermindlabs.org` if it is running `ssh -R chat.hypermindlabs.org:80:…`. Actually, that should work if the script runs the correct SSH command. But mixing Cloudflare’s proxy can complicate SNI/SSL. We strongly recommend **leaving the CNAME as DNS only**. That way, the client (browser) resolves `chat.hypermindlabs.org → serveo.net` directly, TLS handshake happens with Serveo’s Let’s Encrypt or self‐signed cert (ours), and traffic flows straight to your local machine.

---

### 5.4 Verifying Propagation & Testing

1. **Check DNS Propagation** (after the script’s 60-second wait):

   ```bash
   dig @1.1.1.1 CNAME chat.hypermindlabs.org +short
   ```

   You should see:

   ```
   serveo.net.
   ```

   (not a random `xyz.serveo.net`; just `serveo.net`)

2. **Check TXT**:

   ```bash
   dig @1.1.1.1 TXT _serveo-authkey.chat.hypermindlabs.org +short
   ```

   You should see:

   ```
   "SHA256:<your-fingerprint>"
   ```

3. **Make sure Cloudflare’s CNAME is DNS only** (grey cloud) in the UI.  Then test:

   ```bash
   curl -I https://chat.hypermindlabs.org/
   ```

   * You should get `HTTP/2 200` (assuming your Node app responds on `/`).
   * If you see `HTTP/2 502`, re-check that your CNAME is DNS only and that the TXT is correct. Also ensure you ran `ssh -R chat.hypermindlabs.org:80:localhost:<port> serveo.net` (which the script handles for you).

4. **Local HTTPS Tests** (the script also spawned this on port 9443):

   ```bash
   curl -k -I https://localhost:9443/      # should return 200
   curl -k -I https://<LAN_IP>:9443/       # should return 200
   ```

5. **Check Node directly**:

   ```bash
   curl -I http://127.0.0.1:<port>/       # should return 200
   ```

---

## How It Works: Key Points

### 6.1 SSH Key & Fingerprint

* If you don’t already have `~/.ssh/id_rsa.pub`, the script runs:

  ```bash
  ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
  ```

  then uses `ssh-keygen -lf ~/.ssh/id_rsa.pub -E sha256` to compute the fingerprint, which looks like:

  ```
  2048 SHA256:QpVnrJXD96qfx8KxduKxt2i9mB3JnVbK8GVoFlk7Ybo user@host (RSA)
  ```

  We extract the part after `SHA256:` (no prefix).

### 6.2 TXT Record Naming

* **Serveo’s requirement:** For a custom domain (e.g. `chat.example.com`), you must have a TXT record at:

  ```
  _serveo-authkey.chat.example.com = SHA256:<fingerprint>
  ```
* Once Serveo sees that TXT, it knows that the owner of that SSH key is authorized to bind `chat.example.com`.

### 6.3 CNAME Target for Custom Domain

* To claim a custom domain, Serveo needs **exactly**:

  ```
  chat.example.com  → CNAME → serveo.net
  ```

  (proxied = OFF in Cloudflare).

* **Why not** point to the ephemeral `xyz.serveo.net`? Because Serveo will only route traffic for a domain if the CNAME is to `serveo.net`.  If you point to `xyz.serveo.net`, Serveo treats it as a “plain ephemeral” request, not a “custom domain” request. So the tunnel for `xyz.serveo.net` may work, but not for `chat.example.com`.

### 6.4 Custom-Domain SSH Command

* **DEV (random subdomain)**:

  ```bash
  ssh -R 80:localhost:<port> serveo.net
  ```

  → Forwards a randomly generated `abcdef1234.serveo.net`.

* **PROD (custom domain)**:

  ```bash
  ssh -R chat.example.com:80:localhost:<port> serveo.net
  ```

  → Serveo reads DNS `_serveo-authkey.chat.example.com`, verifies your key, then binds `chat.example.com` to your localhost port.

### 6.5 SSL Certificates + Local HTTPS

* The script creates a multi-SAN certificate that covers all relevant names:

  ```
  - "localhost"
  - "<LAN_IP>"             # e.g. "192.168.1.42"
  - "<real_domain>"        # e.g. "chat.hypermindlabs.org" (only in PROD)
  - "<tunnel_domain>"      # e.g. "abcdef1234.serveo.net"
  - "127.0.0.1"
  ```

* If **mkcert** is installed, it uses mkcert to generate a locally-trusted cert. Otherwise it falls back to a self-signed certificate (which your browser will warn about, but you can bypass).

* It launches an HTTPS server on port **9443** that proxies all traffic to your Node app on `localhost:<port>`.

---

## Troubleshooting

### 7.1 502 Errors from Cloudflare

* **Symptoms**:

  * You see `HTTP/2 502` when curling `https://chat.example.com/`, even though `curl http://abcdef1234.serveo.net/` → `200`.

* **Cause**:

  * Cloudflare is in “Proxied” mode (orange cloud). It attempts to proxy `chat.example.com` to an origin of `chat.example.com` (Host header), but the CNAME points to `serveo.net`. Cloudflare is forwarding traffic with `Host: chat.example.com` to Serveo’s origin. Serveo only binds `chat.example.com` if you did the **custom-domain** SSH (`-R chat.example.com:80:…`). If you didn’t do that exact SSH or if you left CNAME proxied, Serveo will not route correctly → 502.

* **Fix**:

  1. In Cloudflare’s DNS panel, ensure the **CNAME** record for `chat.example.com` is set to **“DNS only”** (grey cloud).
  2. If you truly need Cloudflare’s proxy, you must use a **Cloudflare Worker** or the paid “Origin Host Header” feature to rewrite the Host header that goes to Serveo → beyond this README’s scope. The simplest route is to leave it DNS only.

### 7.2 “Unable to find active zone” Errors

* **Symptoms**:

  ```
  ❌ Unable to find active zone 'hypermindlabs.org' in Cloudflare. Response: ...
  ```

* **Cause**:

  * Either your Cloudflare API token doesn’t have permission or you typed the zone name incorrectly.
  * Make sure:

    * Your token has “Zone → DNS → Edit” on that specific zone.
    * The zone name is exactly your root domain (e.g. `hypermindlabs.org`), not including “[www.”](http://www.”)

* **Fix**:

  1. Log in to Cloudflare → Dashboard → DNS → look at the Zone name.
  2. Go to **Profile → API Tokens → edit** that token → verify “Zone Resources → Include → Specific zone → hypermindlabs.org” is correct.
  3. Use that exact zone name in the prompt.

### 7.3 SSL Certificate Issues

* **Self-signed**: Your browser will warn. You can safely click through (on `https://localhost:9443` or `https://chat.example.com` if you accept the self-signed).
* **mkcert**: If you run `brew install mkcert` (macOS) or follow [mkcert instructions](https://github.com/FiloSottile/mkcert), then `./server.py` calls `mkcert -install` and automatically trusts your local CA. You’ll get no warnings for `localhost`, LAN IP, or `chat.example.com` (because mkcert obtains a valid certificate from your local trusted CA).

---

## Appendix: Useful Links

* **Cloudflare API Tokens**
  Create an API token with “Edit zone DNS” permissions:
  [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)

* **Cloudflare Developer Docs**

  * List / Create / Update DNS records:
    [https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records)
    [https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record)
    [https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record)

* **Serveo Custom Domain Docs**
  (Scroll to “Custom Domain” section)
  [https://serveo.net/](https://serveo.net/)

* **mkcert** (optional, for local-trusted certificates)
  [https://github.com/FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)

* **ssh-keygen fingerprint**
  To manually compute a key’s fingerprint:

  ```bash
  ssh-keygen -lf ~/.ssh/id_rsa.pub -E sha256
  ```

---

### Summary

* **DEV mode** is for quick local tests: random `*.serveo.net` + local HTTPS.
* **PROD mode** uses Cloudflare + a custom subdomain.  The script automatically:

  1. Creates a CNAME to `serveo.net` (DNS only).
  2. Creates a TXT `_serveo-authkey… = SHA256:<fingerprint>`.
  3. Waits, then runs `ssh -R chat.example.com:80:localhost:<port> serveo.net` so Serveo binds your domain.
  4. Generates a certificate and starts a local HTTPS reverse-proxy on 9443.

After that, visiting **`https://chat.example.com`** in your browser should connect directly through Serveo to your local Node, without any 502 errors.

Enjoy seamless Dev + Production tunnels!
