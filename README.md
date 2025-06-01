# Serveo Local Development and Production Forwarder

A single-command installer + orchestrator for:
- **DEV mode** → quick HTTPS (https://localhost:9443) + random `*.serveo.net` tunnel → your local Node.  
- **PRODUCTION mode** → Cloudflare DNS (CNAME + TXT) + custom subdomain (e.g. `chat.yourdomain.com`) → Serveo tunnel → local Node.

Everything lives in one Python script (`server.py`) on GitHub. This README shows you how to run it in a single shell line, and explains all the pieces if you need to troubleshoot.

---

## 📋 Prerequisites

1. **Node.js & npm** (v14.x or higher).  
   Confirm:  
   ```bash
   node --version 
   npm --version
```

2. **Python 3** (≥ 3.7) and `pip`.
   Confirm:

   ```bash
   python3 --version 
   pip3 --version
   ```

3. **ssh (OpenSSH client)**
   Confirm:

   ```bash
   ssh -V
   ```

4. **Cloudflare account** → for PRODUCTION mode. You’ll need to create an API Token with “Edit zone DNS” for your domain.
   (See detailed steps below.)

5. A **Node.js project** in the **same folder** as `server.py`, containing:

   * `package.json`
   * `server.js` (or equivalent entrypoint)

   The Node app must read `process.env.PORT` and listen on that port. The script will set `PORT=<free_port>` before launching.

---

## 🚀 One-Line Installation & Run

Run this single command in your terminal. It:

1. Downloads `server.py` from GitHub
2. Makes it executable
3. Executes it under Python 3—auto-creating a `venv/` and installing `cryptography` & `requests`
4. Prompts you to choose DEV vs PRODUCTION
5. Proceeds with either random Serveo subdomain (DEV) or Cloudflare + custom domain (PROD).

```bash
curl -fsSL https://raw.githubusercontent.com/robit-man/serveo-local-dev/main/server.py \
  -o ~/serveo-launcher.py && chmod +x ~/serveo-launcher.py && python3 ~/serveo-launcher.py
```

* **What this does:**

  1. `curl -fsSL <URL> -o ~/serveo-launcher.py` → downloads `server.py` into your home folder as `serveo-launcher.py`.
  2. `chmod +x ~/serveo-launcher.py` → makes it executable.
  3. `python3 ~/serveo-launcher.py` → runs the script with Python 3.

After that, follow the on-screen prompts.

---

## 📑 Detailed Steps & Explanations

### 1. First Run: Virtualenv + Dependencies

When you run `serveo-launcher.py` for the first time, it will:

1. Look for `venv/` in the same directory. If not present:

   ```bash
   python3 -m venv venv
   ```
2. Activate that venv and run:

   ```bash
   pip install cryptography requests
   ```
3. Re-exec itself inside `venv/`, so all imports work out of the box.

**Outcome:** a local Python venv with all necessary modules, and then you’ll see a prompt asking “DEV or PRODUCTION?”

---

### 2. Choose Mode

After the venv is ready, you’ll see:

```
⚠ Do you want to run in DEV mode or PRODUCTION mode?
   1) DEV (no Cloudflare, just random Serveo subdomain)
   2) PRODUCTION (Cloudflare + custom subdomain)
Enter 1 or 2:
```

* Type `1` and press Enter → **DEV mode**
* Type `2` and press Enter → **PRODUCTION mode**

---

### 3. DEV Mode (Option 1)

If you choose **DEV**, the script will:

1. Pick a free port for your Node app (starts at 3000, increments if busy).
2. Run `npm install` (if `package.json` exists).
3. Start your Node process with `PORT=<chosen_port> npm run start`.
4. Generate (or reuse) `~/.ssh/id_rsa` & `~/.ssh/id_rsa.pub`, compute the SSH key’s SHA256 fingerprint.
5. Launch a random Serveo tunnel with:

   ```bash
   ssh  -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -R 80:localhost:<app_port> serveo.net
   ```

   Serveo picks a random subdomain (e.g. `abcdef1234.serveo.net`) and reports:

   ```
   Forwarding HTTP traffic from https://abcdef1234.serveo.net to localhost:<app_port>
   ```
6. Generate a multi-SAN certificate covering:

   * `localhost`
   * your LAN IP (e.g. `192.168.1.42`)
   * the random `abcdef1234.serveo.net`
   * `127.0.0.1`
   * (If you have `mkcert` installed, it uses mkcert; otherwise it falls back to a self-signed.)
7. Start a local HTTPS reverse proxy on port **9443** that forwards to `http://127.0.0.1:<app_port>`.

You’ll see a banner like:

```
╔═══════════════════════════════════════════════════╗
║  Node (HTTP)  → http://127.0.0.1:3015             ║
║  Local Dev    → https://localhost:9443            ║
║  LAN Dev      → https://192.168.1.42:9443         ║
║  Production   → https://abcdef1234.serveo.net     ║
╚═══════════════════════════════════════════════════╝

✅ Development will be accessible at: https://abcdef1234.serveo.net (via Serveo)
⚠ All services started. Press Ctrl+C to terminate.
```

**DEV Mode Quick Tests:**

```bash
curl -I http://127.0.0.1:<app_port>/       # → 200
curl -k -I https://localhost:9443/         # → 200 (ignore cert warning)
curl -k -I https://<LAN_IP>:9443/          # → 200
curl -I https://abcdef1234.serveo.net/     # → 200
```

---

### 4. PRODUCTION Mode (Option 2)

If you choose **PRODUCTION**, the script will prompt for:

```
⚠ Before proceeding, make sure you have a Cloudflare API Token with “Edit zone DNS” permissions for your zone.

Cloudflare API Token     : <YOUR_CLOUDFLARE_TOKEN>
Cloudflare Zone Name     : <your-domain.com>
Subdomain (e.g. chat)    : <subdomain>
DNS TTL (secs) [300]: <TTL or press Enter for 300>
```

* **Cloudflare API Token**:

  * Must have “Zone → DNS → Edit” for your domain (or more granular permissions limited to your zone).
  * ⚠ Copy it now. The script will store it in `domain.conf` but you should still keep a secure backup.

* **Cloudflare Zone Name**:

  * Your root domain exactly as it appears in Cloudflare (e.g. `hypermindlabs.org`).
  * Do not include “http\://” or “[www.”](http://www.”).

* **Subdomain**:

  * The label you want to claim (e.g. `chat`). The full custom domain will become `chat.hypermindlabs.org`.

* **TTL**:

  * DNS TTL for the new records (default 300 seconds).

Once you fill those in, the script:

1. Verifies your Cloudflare token/zone by calling:

   ```
   GET https://api.cloudflare.com/client/v4/zones?name=<your-domain.com>&status=active
   ```

2. Fetches the **zone\_id** from the JSON response.

3. Generates (or reuses) `~/.ssh/id_rsa` & `id_rsa.pub` and computes SHA256 fingerprint.

4. **Creates/updates two DNS records** via Cloudflare API:

   * **CNAME**

     ```
     Name:  <subdomain>.<zone_name>
     Type:  CNAME
     Content:  serveo.net
     TTL:  <TTL>
     Proxy status:  DNS only (OFF)
     ```

     → e.g. `chat.hypermindlabs.org  CNAME  serveo.net  (TTL=300)`

   * **TXT**

     ```
     Name:  _serveo-authkey.<subdomain>.<zone_name>
     Type:  TXT
     Content:  "SHA256:<fingerprint>"
     TTL:  <TTL>
     ```

     → e.g. `_serveo-authkey.chat.hypermindlabs.org  TXT  "SHA256:QpVnrJX..."  (TTL=300)`

   Sample Cloudflare API calls under-the-hood:

   ```http
   POST https://api.cloudflare.com/client/v4/zones/<zone_id>/dns_records
   { 
     "type":"CNAME", 
     "name":"chat.hypermindlabs.org", 
     "content":"serveo.net",
     "ttl":300,
     "proxied":false
   }

   POST https://api.cloudflare.com/client/v4/zones/<zone_id>/dns_records
   { 
     "type":"TXT", 
     "name":"_serveo-authkey.chat.hypermindlabs.org",
     "content":"SHA256:QpVnrJX...",
     "ttl":300
   }
   ```

5. **Waits \~60 seconds** (Cloudflare TTL) for DNS propagation.
   You’ll see:

   ```
   ⏳ Waiting 60 seconds for DNS to propagate … (Cloudflare TTL is 300 s)
   ```

6. **Launches** Serveo tunnel with custom‐domain binding:

   ```bash
   ssh  -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
       -R <subdomain>.<zone_name>:80:localhost:<app_port> serveo.net
   ```

   e.g.

   ```bash
   ssh  -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
       -R chat.hypermindlabs.org:80:localhost:3015 serveo.net
   ```

   Once Serveo verifies the TXT record (`_serveo-authkey.chat.hypermindlabs.org`) and your SSH key fingerprint, it will reply:

   ```
   Forwarding HTTP traffic from https://chat.hypermindlabs.org to localhost:3015
   ```

   and the script prints:

   ```
   ✅ Serveo tunnel established: https://chat.hypermindlabs.org
   ```

7. Generates a multi-SAN certificate covering:

   * `localhost`
   * your LAN IP (e.g. `192.168.1.42`)
   * `chat.hypermindlabs.org`
   * the ephemeral Serveo host (if any)
   * `127.0.0.1`
     (Uses **mkcert** if installed, else self-signed.)

8. Starts a local HTTPS reverse proxy on port **9443** → `http://127.0.0.1:<app_port>`.

9. Prints a banner:

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

## 🔍 Verify DNS & Tunnel

1. **Check CNAME** (after \~60 s):

   ```bash
   dig @1.1.1.1 CNAME chat.hypermindlabs.org +short
   # → serveo.net.
   ```

2. **Check TXT**:

   ```bash
   dig @1.1.1.1 TXT _serveo-authkey.chat.hypermindlabs.org +short
   # → "SHA256:<fingerprint>"
   ```

3. **Ensure Cloudflare’s CNAME record is “DNS only”** (grey cloud).
   If it’s **Proxied (orange cloud)**, you’ll see 502 errors because Cloudflare would be fronting the SSL handshake. Custom-domain Serveo only works when Cloudflare is set to **DNS only** for that CNAME.

4. **Test Production endpoint**:

   ```bash
   curl -I https://chat.hypermindlabs.org/ 
   # → HTTP/2 200 OK (if your Node app’s `/` responds)
   ```

5. **Local HTTPS** (for dev/test):

   ```bash
   curl -k -I https://localhost:9443/       # → 200
   curl -k -I https://<LAN_IP>:9443/        # → 200
   curl -I http://127.0.0.1:<app_port>/      # → 200
   ```

---

## ⚙️ How It All Works / Key Points

1. **SSH Key & Fingerprint**

   * If `~/.ssh/id_rsa.pub` doesn’t exist, the script runs:

     ```bash
     ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
     ```
   * It then runs:

     ```bash
     ssh-keygen -lf ~/.ssh/id_rsa.pub -E sha256
     ```

     to extract a fingerprint like `SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz…`.

2. **TXT Record Naming**

   * Serveo’s **Custom Domain** requirement:

     ```
     _serveo-authkey.<subdomain>.<zone> = SHA256:<fingerprint>
     ```

     Example:

     ```
     _serveo-authkey.chat.hypermindlabs.org = "SHA256:QpVnrJXD96qx…"
     ```

3. **CNAME Target for Custom Domain**

   * For a custom domain `chat.hypermindlabs.org`, the CNAME must point to `serveo.net` (not `abcdef1234.serveo.net`).
   * Example:

     ```
     chat.hypermindlabs.org  CNAME  serveo.net  (TTL=300, proxied=OFF)
     ```

4. **Custom-Domain SSH Command**

   * DEV (ephemeral subdomain):

     ```bash
     ssh -R 80:localhost:<port> serveo.net
     ```

     → Serveo assigns you a random `abcdef1234.serveo.net`.
   * PROD (custom domain):

     ```bash
     ssh -R chat.hypermindlabs.org:80:localhost:<port> serveo.net
     ```

     Serveo looks up `_serveo-authkey.chat.hypermindlabs.org`, verifies your fingerprint, then binds `chat.hypermindlabs.org` to your local port.

5. **SSL Certificates & Local HTTPS**

   * The script generates a multi-SAN cert for:

     ```
     localhost, <LAN_IP>, <real_domain (if prod) />, <serveo_host (random or custom)>, 127.0.0.1
     ```
   * If you’ve installed [mkcert](https://github.com/FiloSottile/mkcert) and run `mkcert -install`, the script uses mkcert for a locally-trusted cert. Otherwise it falls back to self-signed (you’ll have to bypass the warning).

6. **Cloudflare Proxy Status**

   * **Always leave the “CNAME → serveo.net” record as DNS only** (grey cloud).
   * If you switch it ON (orange cloud), Cloudflare proxies your request, sends `Host: chat.hypermindlabs.org` to Serveo’s IP. Serveo sees `Host: chat.hypermindlabs.org` *but* the CNAME points to `serveo.net`. This confuses Serveo’s routing, resulting in a 502.
   * For a simple Serveo tunnel, you don’t need Cloudflare’s CDN/proxy layer—just DNS.

---

## 🛠 Troubleshooting

### 1. “502” from `https://chat.hypermindlabs.org/`

* **Likely cause:** Cloudflare CNAME was set to “Proxied (orange cloud).”
* **Fix:** In your Cloudflare dashboard → DNS → locate the CNAME for `chat…` → toggle it to **“DNS only”** (grey cloud). Wait a few seconds, then retry `curl -I https://chat.hypermindlabs.org/` → 200.

### 2. “Unable to find active zone” Errors

* **Symptoms:**

  ```
  ❌ Unable to find active zone 'hypermindlabs.org' in Cloudflare. Response: { “result”:[], “success”:true, … }
  ```
* **Cause:**

  * You typed the zone name incorrectly (e.g. `www.hypermindlabs.org` instead of `hypermindlabs.org`).
  * Your API token doesn’t have the correct permissions or isn’t scoped to that zone.
* **Fix:**

  1. In Cloudflare → Dashboard → DNS, verify your zone name exactly (e.g. `hypermindlabs.org`).
  2. In Cloudflare → Profile → API Tokens, ensure your token has “Zone → DNS → Edit” for **that specific** zone.
  3. Run the script again and enter the correct zone name + token.

### 3. SSH Key / Fingerprint Errors

* If `ssh-keygen` fails, ensure OpenSSH is installed.
* Check that `~/.ssh/id_rsa.pub` exists. The script will auto-generate a 2048-bit RSA key if not found.

### 4. SSL / mkcert Warnings

* **mkcert installed?**

  * If you have `mkcert`: the script runs `mkcert -install` and issues a cert trusted by your OS/browser. No warnings.
  * If you do **not** have `mkcert`: the script creates a self-signed cert. Browsers will show “Not secure” for `https://localhost:9443` (you can bypass). That’s expected.

---

## 🔗 Appendix: Useful Links

* **GitHub script source** (always gets the very latest `server.py`):
  [https://github.com/robit-man/serveo-local-dev/blob/main/server.py](https://github.com/robit-man/serveo-local-dev/blob/main/server.py)

* **Raw download link** (the single-line installer uses this):

  ```
  https://raw.githubusercontent.com/robit-man/serveo-local-dev/main/server.py
  ```

* **Cloudflare API Tokens**
  Create a token with “Edit zone DNS” permission:
  [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)

* **Cloudflare DNS API Docs**

  * List zones:
    [https://developers.cloudflare.com/api/operations/zones-list](https://developers.cloudflare.com/api/operations/zones-list)
  * DNS Records:
    [https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records)
    [https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record)
    [https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record](https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record)

* **Serveo Custom Domain Docs**
  (Scroll to “Custom Domain” section)
  [https://serveo.net/](https://serveo.net/)

* **mkcert** (for local trusted certs)
  [https://github.com/FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)

---

### Quick Recap

```bash
curl -fsSL https://raw.githubusercontent.com/robit-man/serveo-local-dev/main/server.py \
  -o ~/serveo-launcher.py && chmod +x ~/serveo-launcher.py && python3 ~/serveo-launcher.py
```

1. Choose **DEV** if you want a quick random `*.serveo.net` tunnel + local HTTPS.
2. Choose **PRODUCTION** if you want a **Cloudflare + custom subdomain** (`chat.yourdomain.com`).

   * Provide your **Cloudflare API Token**, **Zone Name**, **Subdomain**, and **TTL** when prompted.
   * The script automatically creates:

     * `chat.yourdomain.com → CNAME → serveo.net` (DNS only)
     * `_serveo-authkey.chat.yourdomain.com → TXT → "SHA256:<fingerprint>"`
   * Wait \~60 s, then the script runs:

     ```bash
     ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
         -R chat.yourdomain.com:80:localhost:<port> serveo.net
     ```
   * Serveo verifies the TXT @ `_serveo-authkey.chat…` and binds your domain.

After that, go to `https://chat.yourdomain.com/` in your browser (or `curl -I`) and you should see your Node app’s response (HTTP 200) without any 502.

Press **Ctrl+C** to shut everything down (Node, SSH tunnel, local HTTPS proxy).
