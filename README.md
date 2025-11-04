# epha (`epha-ots`)

`epha-ots` is an in-memory, one-time secret drop box. It lets you exchange a single encrypted payload between two parties without ever writing the cleartext or ciphertext to disk. The client runs in the browser; the server is a small HTTPS daemon that stores blobs in RAM until they are retrieved once or they expire.

## Demo

https://local.tanuki-gecko.ts.net/ 

https://local.tanuki-gecko.ts.net/status 

The instance is only sometimes available because it runs from my laptop.

## Features

- Client-side AES-GCM encryption with a fresh 256-bit key, nonce, and salt for every secret (WebCrypto-based).
- HKDF-derived blob IDs bound into the AEAD AAD so stored payloads cannot be swapped between identifiers.
- RAM-only blob store with a fixed 1 hour TTL and ~262k entry capacity; blobs vanish immediately after their first successful GET.
- Optional password wrapping that adds a second AES-GCM layer without revealing password usage to the server.
- Server or URL-observer cannot guess whether a password was used or not. 
- Optional Tailscale-aware forwarding when compiled with `-DTAILSCALE=ON`.
- QR code generation and share links in the form `https://host/#<id>/<key>` for easy transfer between devices.

## Build & Run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# HTTP development mode
./build/epha-ots --http --port 9000

# HTTPS (provide your own cert/key)
./build/epha-ots --port 8443 --cert cert.pem --key key.pem
```

The client UI is served from `client.html`. You can host it statically or let the bundled server deliver it from the root endpoint.

## Local quick-up using Tailscale

 The fastest way to be UP is to use automatically requested certs from Let's Encrypt. Tailscale claim they do not steal them. You must use either `-DTAILSCALE=ON` build option or `-DDEBOUNCER=OFF`.

```bash
# install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# run tailscale daemon, it will give you a link to authenticate
sudo tailscale up
# as from now, you maybe want to change the machine name and obtain fancy tailscale subdomain

# run the funnel, it will give you a link to enable the feature in your account
sudo tailscale funnel --https=443 http://127.0.0.1:8443

# run epha without TLS
./build/epha-ots --http

```

Docs:
- https://tailscale.com/kb/1311/tailscale-funnel
- https://tailscale.com/kb/1153/enabling-https

Alternatively you can use Tor onion-service. Do not pass plaintext data over the Tor network, use HTTPS.

## CMake building options

You can control compile-time features via CMake options.

- `JS_MINIFY` (default `OFF`): use the minified JS bundle (`client.min.js`).
- `FILELOG` (default `OFF`): write server logs to `epha.log`.
- `SYSLOG` (default `ON`): send logs to the system logger.
- `TRACY_ENABLE` (default `OFF`): pull in Tracy client code and instrument the hot paths.
- `STATISTICS` (default `OFF`): track detailed storage allocator, request, and debouncer counters (dumped to the log on shutdown). Also makes `/status` more verbose.
- `LOCK_MEMORY_TO_RAM` (default `OFF`): call `mlock` on storage buffers to avoid swapping.
- `TAILSCALE` (default `OFF`): trust the `X-Forwarded-For` header from Tailscale funnel.
- `ASSEMBLED_HTML` (default `ON`): serve the pre-built `client_assembled.html` asset.
- `DEBOUNCER` (default `ON`): enable simple per-client request debouncing.
- `SIMD_X86` (default `ON`): compile AVX2/SSE-accelerated code paths.
- `SIMD_ARM` (default `OFF`): compile ARM NEON code paths for capable devices.

Examples:

```bash
# Debug
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSYSLOG=OFF -DSTATISTICS=ON
cmake --build build -j

# Release
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DJS_MINIFY=ON -DSIMD_X86=ON
cmake --build build -j

# Release for Tailscale without debouncer
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DJS_MINIFY=ON -DSIMD_X86=ON -DDEBOUNCER=OFF
cmake --build build -j
```

In order to minify javascript, you need uglify-js, which can be installed that way:

```bash
npm install uglify-js -g
```

## Key generation

```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```

## Android

You can build epha-ots in termux. Download the latest snapshot and unpack it:

```bash
curl -L -o epha-ots.zip https://github.com/x6prl/epha-ots/archive/refs/heads/master.zip
unzip epha-ots.zip
cd epha-ots-master
```

Then install the build dependencies and run the helper script:

```bash
pkg install clang libmicrohttpd openssl-tool
./tools/build_android.sh
# generate a key and a certificate
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
# now you may run
./epha-ots
```

## Protocol Overview

1. Generate three random values: key **K**, initialization vector **N**, and salt **S**. K is 256-bit, N is 96-bit, S is 128-bit.
2. Derive **ID** from **K** and **S** (HKDF based on SHA-256).
3. Build the additional authenticated data string **aad** — it’s just a string of the form `id=ID`.
4. If the user has set a password:
   • Derive **Pk** from the password and **S** (PBKDF2, SHA-256, 800000 iterations). A single salt is used for everything.
   • Encrypt the data with AES-GCM using key **Pk**, IV/nonce **N**, and supplying **aad**.
5. Append a two-byte tag to the already encrypted data (if there was a password) or to the original data (if there was no password). The first byte is meaningful — it indicates whether the data are password-encrypted (**0x73**) or not (**0x13**). The second byte is the constant **0x37**.
6. Encrypt the result with AES-GCM again, using the same iv = **N** and the same **aad**. This produces the final ciphertext **ct**.
7. Concatenate bytes to form the string **blob = N .. S .. ct**.
8. Send **blob** to the server together with **ID**. The server returns **blob** by that **ID** and cannot substitute it: the client will verify **ID** first using **N** and **K** even before decryption, and then via **aad**.
9. The client keeps **K**; **K** is never sent to the server. **Pk** as well; anything password-related is wiped.
10. The client forms a link `origin/#ID/K`. Here **ID** and **K** are base64url strings.
11. When the recipient opens the link:
    • The browser strips everything starting with `#` — this is called `location.hash`.
    • The client app is loaded from the server (which, in my view, is the main hole: we’re essentially back to “TLS is leaky”; however, nothing prevents keeping the client offline; ideally there should be a standalone client).
    • The client-side JS checks `location.hash`, and if it contains **ID** and **K**, it fetches the data from the server.
    • It verifies, decrypts, and, if needed, asks for a password and decrypts again.

## Support the development

### ETH

```
0xA33dbE6d7c49b76Bb3c22cbfd2B0d83597709008
```

### BTC

```
bc1qnnhvqhpmkglv2gmejmjr06a7f0aktxmrt7n586
```

### XMR

```
45dwLodwU3vLE6XHojBY7m1w7T9NH6dEiagfKmGzo7Fu4SDLYgfcjzn9rYxb55DcSYGp3qA2PkKoz8WWECxGDitqU8u8itB
```

## License

This project is licensed under the GNU General Public License v3.0. See `LICENSE` for the full text.

[QRCode.js](https://davidshimjs.github.io/qrcodejs/) is under MIT license.

## TODO

- storage memory encryption, because now it can leak to swap as is IF ulimits unchanged
- service worker for TOFU?
- additional not-so-fancy web client
- storage duration options
- canary
- "second" password for receiving a blob
- "fake" password for canary?
- link-based one-time-chatty
- images and files
- password strength/generator
- separate client (maybe with quantum-safe crypto?)

## Misc

### Dev tools

- `tools/assemble_html.py` — inlines `client.css`, `qrcode.js`, and `client.js` into `assets/client_assembled.html`. Run `python tools/assemble_html.py` whenever you tweak the web client and want the single-file bundle served by the daemon.
- `tools/blob_bench.py` — async load generator for the `/blob` API, but not a benchmark. Spins up cleanly inside a virtualenv (`python -m venv venv && source venv/bin/activate`) with `pip install httpx`. Inspect options with `python tools/blob_bench.py --help`; defaults target a local release server on `https://127.0.0.1:8443`.
- `tools/build_android.sh` — Termux-friendly build wrapper that uses the system `clang` and links against `libmicrohttpd` from `$PREFIX`. Invoke it inside Termux after installing the listed dependencies.
- `tools/build_tests.sh` — quick compiler shortcut for the linear-probing unit test. Produces `build/lp_test`.
- `tools/minify.sh` — minifies `qrcode.js` and `client.js` into their `.min.js` counterparts using `uglifyjs`. Install the tool globally (`npm install -g uglify-js`) before running the script.

### Comparison to OneTimeSecret

**1) Threat model & trust**

* **OneTimeSecret (OTS):** Browser sends plaintext over TLS; server encrypts at rest and can decrypt again on view. You must trust the server/operator not to read/log.
* **epha-ots:** Browser generates a 32-byte random key `K`, does **AES-GCM** locally, and sends only `N || S || ct` to the server. The server never learns `K`; it can’t decrypt—**zero-knowledge** by default.

**2) Key management & identifiers**

* **OTS:** Single server key (derived from instance secret) encrypts everyone’s data. Exposure of that key compromises all stored secrets.
* **epha-ots:** Fresh, per-secret **random** `K` (256 bits). There’s no global key to steal.

**3) Cipher & integrity binding**

* **OTS:** Typically AES-256-CBC with separate MAC logic in backend libraries; integrity relies on server-side handling and metadata checks.
* **epha-ots:** **AES-GCM** with `aad="id="+ID`, so the ciphertext is **cryptographically bound to the exact ID**; any mismatch or swap (e.g., serving blob under a different path) fails authentication.

**4) Link structure & leakage**

* **OTS:** Share URL is a lookup token; the decryption key lives on the server, so the link alone lets the server (and anyone with server access) recover plaintext.
* **epha-ots:** Share URL is `…/#<ID>/<base64url(K)>`. The **key is in the URL fragment**, which browsers do **not** send to servers over HTTP(S). Even if the path leaks to logs or a preview bot hits it, the bot can’t decrypt without the fragment.

**5) Storage semantics**

* **OTS:** Encrypted at rest (often in Redis) with a TTL; decrypted and destroyed on first view (server decides).
* **epha-ots:** **RAM-only** blob store; evicted/expired or deleted immediately after first GET. No disks, no long-term traces, smaller forensic surface.

**6) Code surface & auditability**

* **OTS:** Mature Ruby stack, multiple components; harder for a single reader to audit end-to-end.
* **epha-ots:** Small enough to mentally model. Lower complexity → fewer hiding spots.

**7) Failure modes**

* **OTS:** If server key is compromised or insiders misbehave, secrets are exposed.
* **epha-ots:** If the server is compromised, attacker can delete or serve stale blobs, but cannot decrypt past blobs without `K`.

### What epha-ots does **not** protect against

* **SWAPing:** The maximum size that may be locked into memory is very small by default for unprivileged users. Running the server by yourself you are responsible for possible swapping of the storage. Please refer to `storage_init` function in `storage.c` and `LOCK_MEMORY_TO_RAM` feature, that is OFF by default.
* **Malicious front-end code:** If the served HTML/JS is modified (server compromise, CDN injection, extension injecting scripts), it can read `location.hash` and exfiltrate `K` before/after decryption. Fragment secrecy helps only if the JS is honest.
* **Host/device compromise:** Keyloggers, clipboard snoopers, screen grabbers, MDM/AV hooks, corporate proxies, or a rooted/jailbroken phone will see plaintext or the fragment key.
* **Browser extensions & injected content:** Over-permissive extensions can access page DOM and the URL fragment; some “productivity” extensions phone home.
* **Side channels & metadata:** Adversaries can learn **that** a secret was exchanged, when, and its approximate size (ciphertext length) from traffic patterns or logs. Also IP metadata.
* **Post-decrypt mishandling:** Once the recipient’s browser shows plaintext, anything they copy/download/store (or their autosave/history/snapshots) is out of scope.
* **Protocol downgrade / misconfig:** Serving the client over HTTP or allowing old TLS ciphersuites invites active MitM before encryption happens client-side.
* **Visibility to local network/middleboxes:** Even with TLS, some enterprise TLS interception boxes (installed root CAs) can see all traffic and hence the page+JS (and thus the fragment).
* **Rendering in hostile containers:** In-app browsers (messengers) may inject code; they also love link-previews → DoS.

---

### Technologies / components you **must** trust (or at least account for)

* **Browser engine & JS runtime:** Correct handling of URL fragments, WebCrypto (or crypto libs), TypedArrays, timing side-channels, and CSP enforcement.
* **Your **exact** front-end bytes:** The HTML/JS/CSS as delivered must be the code you intended (no in-flight modification). If hosted, you trust the host + CDN. If local/offline, you trust your distribution channel.
* **Entropy sources:** `window.crypto.getRandomValues()` must be present and healthy.
* **Crypto implementations:** AES-GCM and HKDF must be correct and side-channel-hardened.
* **TLS/PKI stack:** Correct certificate validation, HSTS, no mixed content, sane ciphers. You inherently trust your chosen CA ecosystem.
* **DNS resolution path:** Your resolver/DoH/DoT provider; otherwise DNS poisoning can steer users to a phish before TLS.
* **OS & hardware:** Memory safety, no malicious kernel modules, no compromised firmware (IME/UEFI). On mobile: no skimmers or device admin malware.
* **User environment hygiene:** No invasive extensions, password managers with page-injection shenanigans, “security” tools that inject JS, etc.
* **Operational controls on the server:** Even though the server can’t decrypt, you still rely on it to: store blobs faithfully, not rewrite payloads, delete on first read, and implement rate-limits fairly.
