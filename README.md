# Serveo Local Dev / Production Launcher

The script server.py has two modes:
- **DEV mode**: random `*.serveo.net` tunnel + local HTTPS proxy
- **PRODUCTION mode**: Cloudflare DNS (CNAME + TXT) → custom subdomain → Serveo → local Node

---

## 1. One-Line Install & Run (Current Directory)

From **inside your project folder** (where your Node app lives), run:

```bash
curl -fsSL https://raw.githubusercontent.com/robit-man/serveo-local-dev/main/server.py \
  -o server.py \
  && chmod +x server.py \
  && python3 server.py
```

* This:

  1. Downloads `server.py` into the **current directory**.
  2. Makes it executable.
  3. Executes it under Python 3 (it will auto-create a `venv/` and install dependencies).

* **Do not rename** the file; leave it as `server.py`.

---

## 2. Node App Requirements

* Your Node project must have `package.json` and `server.js` (or equivalent).
* The launch script expects `npm run start` to start your server on `process.env.PORT`.

---

## 3. DEV vs PRODUCTION

When you run `python3 server.py`, you will be prompted to choose:

1. **DEV** – no DNS changes.

   * Picks a free port (3000→3020), runs `npm install` + `npm run start`.
   * Spins up a random Serveo tunnel (e.g. `abcdef1234.serveo.net`).
   * Generates a local HTTPS certificate (covers `localhost`, LAN IP, random Serveo host).
   * Starts a local HTTPS reverse proxy on `https://localhost:9443` → `http://127.0.0.1:<port>`.
   * Prints a banner showing your Node URL, local HTTPS, LAN HTTPS, and the random `*.serveo.net`.

2. **PRODUCTION** – sets up Cloudflare DNS + custom subdomain.

   * **Prompts you for**:

     1. **Cloudflare API Token** (must have “Zone → DNS → Edit” for your zone).
     2. **Cloudflare Zone Name** (e.g. `example.com`).
     3. **Subdomain** (e.g. `chat`).
     4. **DNS TTL** (default 300).
   * Automatically creates/updates two DNS records in Cloudflare (DNS only, NOT proxied):

     * **CNAME**  `chat.example.com → serveo.net`  (TTL 300)
     * **TXT**   `_serveo-authkey.chat.example.com → "SHA256:<your-ssh-fingerprint>"`  (TTL 300)
   * Waits \~60 seconds for propagation.
   * Runs `ssh -R chat.example.com:80:localhost:<port> serveo.net` to bind your custom domain.
   * Generates a multi-SAN certificate (covers `localhost`, LAN IP, `chat.example.com`, ephemeral Serveo host, `127.0.0.1`).
   * Starts local HTTPS reverse proxy on `https://localhost:9443` → `http://127.0.0.1:<port>`.
   * Prints a banner showing your Node URL, local HTTPS, LAN HTTPS, and `https://chat.example.com`.

---

## 4. What You Need from Cloudflare (PRODUCTION Mode)

1. **Cloudflare API Token**

   * Go to **Cloudflare Dashboard → Profile → API Tokens → Create Token**.
   * Choose **“Edit zone DNS”** template or give “Zone\:DNS\:Edit” on your specific zone.
   * Copy the token (you’ll paste it into the script when prompted).

2. **Cloudflare Zone Name**

   * Exactly your root domain as it appears in Cloudflare (e.g. `example.com`).
   * Do **not** include `www.` or any protocol.

3. **Subdomain**

   * The label you want (e.g. `chat`). The script will automatically use `chat.example.com`.

4. **DNS TTL**

   * Default 300 seconds (you can press Enter to accept).

After you supply those when prompted, the script will:

* Create/Update `chat.example.com CNAME serveo.net` (DNS only).
* Create/Update `_serveo-authkey.chat.example.com TXT "SHA256:<fingerprint>"` (DNS only).
* Wait \~60 seconds, then run:

  ```bash
  ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
    -R chat.example.com:80:localhost:<port> serveo.net
  ```
* Once Serveo confirms, your custom domain is live.

---

## 5. Verifying & Testing

* **DEV mode**:

  ```bash
  curl -I http://127.0.0.1:<port>/
  curl -k -I https://localhost:9443/
  curl -k -I https://<LAN_IP>:9443/
  curl -I https://<random>.serveo.net/
  ```

* **PRODUCTION mode** (after \~60 s propagation):

  ```bash
  dig @1.1.1.1 CNAME chat.example.com +short   # → “serveo.net.”
  dig @1.1.1.1 TXT _serveo-authkey.chat.example.com +short
    # → “SHA256:<your-fingerprint>”
  curl -I https://chat.example.com/            # → HTTP/2 200 OK
  ```

* **Local HTTPS** (either mode):

  ```bash
  curl -k -I https://localhost:9443/            # → 200
  curl -k -I https://<LAN_IP>:9443/             # → 200
  ```

---

## 6. Shutting Down

Press **Ctrl+C** in the terminal running `server.py` to:

* Terminate the SSH tunnel.
* Kill the Node process.
* Stop the local HTTPS proxy.

---

That’s it—ultra-minimal. You only need:

1. The one-line `curl … -o server.py && chmod +x server.py && python3 server.py`
2. Node app files (`package.json` + `server.js`) in the same directory.
3. (For PRODUCTION) a Cloudflare token, zone name, and chosen subdomain.

Run it, follow prompts, and you’ll have a live tunnel in minutes.
