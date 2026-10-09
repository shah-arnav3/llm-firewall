# llm-firewall

**Status: early implementation.** Only what [Build and test](#build-and-test) lists
runs today. The rest of this document describes the design being built.

llm-firewall is a local monitor for the **Claude desktop app on macOS**. It only
**logs**. It never blocks, modifies or delays traffic. It has exactly two goals:

1. **Log PII going out to Claude**: personal data and secrets in what you send.
2. **Log prompt injection coming in**: injection indicators in *untrusted* content
   (files, tool results, web results) that enters Claude's context.

A third, supporting signal flags model replies that try to exfiltrate data through
links or images. The log holds metadata and masked findings, and **never raw content**.

---

## Contents

- [Goals and non-goals](#goals-and-non-goals)
- [Scope: desktop only](#scope-desktop-only)
- [Verified facts about Claude.app](#verified-facts-about-claudeapp)
- [The three desktop traffic paths](#the-three-desktop-traffic-paths)
- [Life of one message](#life-of-one-message)
- [Certificate model](#certificate-model)
- [What is and is not logged](#what-is-and-is-not-logged)
- [Detectors](#detectors)
- [Failure behavior: fail-open everywhere](#failure-behavior-fail-open-everywhere)
- [Security model of the tool itself](#security-model-of-the-tool-itself)
- [Coverage counters](#coverage-counters)
- [Setup: what it changes on your Mac](#setup-what-it-changes-on-your-mac)
- [Uninstall](#uninstall)
- [Known limits](#known-limits)
- [Phases](#phases)
- [Repository layout](#repository-layout)
- [Build and test](#build-and-test)

---

## Goals and non-goals

**Goals**
- Record every PII or secret finding in outbound content, as a masked preview.
- Record every injection indicator in untrusted inbound content, as a masked excerpt and hash.
- Make blind spots visible: count what was dropped, truncated, unparsed or unrecognized.
- Never affect Claude. If any part of llm-firewall is down, Claude works normally and
  only logging is lost.

**Non-goals**
- Blocking, redacting or rewriting anything.
- Web browsers (for now; see [Scope](#scope-desktop-only)).
- Seeing content the server fetches that never passes through the client.
- Protecting against malware already running as your user.
- Keeping raw prompts or replies "for debugging". There is no such mode.

## Scope: desktop only

Only Claude.app is routed through llm-firewall, and browsers are never touched. This is:

- **Safer.** Nothing else on the machine goes through the proxy, and there is no
  system-wide proxy setting.
- **Tractable.** One client, one Chromium version, and one set of verified behaviors (below).

**Adding web later** is designed as configuration, not new code:
- A system PAC scoped to the same hosts.
- A `clients:` rule in `config/llm-firewall.yaml` that tags browser User-Agents as `WEB`.
- Chrome/Firefox profiles with HTTP/3 disabled. A browser that is not proxied can use
  QUIC and bypass a TCP proxy.
- A validation pass for Safari.

The proxy, pipeline and store are client-agnostic already.

## Verified facts about Claude.app

These were checked against Claude.app **v2.9939.4** (Electron, Chrome 152). The design
depends on them.

- **Main UI traffic uses Chromium's network stack and resolves the proxy**
  (`resolveProxy`). The only `setCertificateVerifyProc` pin in the app is on a
  separate `local-pairing` session partition (the Chrome-extension MCP pairing), not
  on the main session. **A CA trusted by the user therefore works for the main traffic.**
- **The app rejects these command-line switches:** `remote-debugging-port`/`-pipe`,
  `ignore-certificate-errors`, `host-resolver-rules`, `host-rules`,
  `disable-web-security`, `log-net-log`, `net-log-capture-mode`, `ssl-key-log-file`,
  and several launcher/cmd-prefix switches. So debugging-based and key-log-based
  capture is impossible.
- **Proxy command-line flags have no effect.** In phase 0, Claude started with
  `--proxy-pac-url` logged `proxy for https://claude.ai resolved … (direct)` in its
  `main.log` and connected straight to Anthropic.
- **Claude has a managed proxy setting, `egressProxyPacUrl`** (Claude Desktop
  1.44121.1 or later; see Anthropic's
  [network proxy docs](https://claude.com/docs/third-party/claude-desktop/network-proxy)).
  It is read once at launch, only from
  `/Library/Managed Preferences/[<user>/]com.anthropic.claudefordesktop.plist`, which
  macOS writes when a configuration profile carrying it is installed. A profile that
  sets only this key changes Claude's proxy and nothing else.
- **Three traffic paths exist** (next section).
- **HTTP/3 is not a bypass on desktop.** claude.ai advertises `alt-svc: h3`, but
  Chromium does not use QUIC through an HTTP proxy.

## The three desktop traffic paths

All three are routed by one setting: `egressProxyPacUrl` points at the PAC that the
proxy serves (`http://127.0.0.1:18443/proxy.pac`). The PAC sends only Claude and
Anthropic hosts to the proxy.

| Path | What | How it is routed | How TLS is trusted | Coverage |
|---|---|---|---|---|
| **(a) App** | The claude.ai UI and the app's own requests (Electron/Chromium) | The app fetches the PAC at launch and evaluates it per request | The local CA in the login Keychain | Phase 0 confirms |
| **(b) Claude Code engine** | The agent behind Chat, Cowork and Code | The app hands it the one proxy the PAC returns for the inference endpoint, as `HTTPS_PROXY`/`HTTP_PROXY` with a loopback `NO_PROXY` | Not settled: the app makes the engine trust the System keychain; `NODE_EXTRA_CA_CERTS` is the documented fallback | Phase 0 confirms |
| **(c) Cowork VM** | Commands the agent runs in Cowork's sandbox | The VM is given its own copy of the PAC when it starts and evaluates it per request, reaching the host's loopback through an alias | Its own trust store: open question | **Phase 0 checks** |

`HTTPS_PROXY` has no per-host rules, so path (b) sends **all** its HTTPS traffic to the
proxy. The proxy therefore also acts as a plain CONNECT tunnel for every host it does
not decrypt (a "blind tunnel", which is never decrypted).

## Life of one message

You type a prompt in Claude.app and press Enter.

```
 Claude.app   (egressProxyPacUrl = http://127.0.0.1:18443/proxy.pac, fetched at launch)
   │  PAC: https/wss to claude.ai, *.claude.ai, anthropic.com, *.anthropic.com
   │       → "PROXY 127.0.0.1:18443; DIRECT"      (everything else → DIRECT)
   ▼
 ┌──────────────────────────── llmfw-proxy (C++, loopback only) ───────────────────────────┐
 │ CONNECT claude.ai:443                                                                    │
 │   scope? ──no──► blind tunnel (bytes relayed, never decrypted, metadata only)            │
 │   yes                                                                                    │
 │   ├─ open NEW upstream TLS to claude.ai, STRICT verify (macOS trust + hostname)          │
 │   │     verify fails ──► blind tunnel (client verifies for itself)                       │
 │   ├─ 200 Connection Established                                                          │
 │   ├─ client TLS with pre-issued leaf cert (ALPN http/1.1)                                │
 │   └─ HTTP/1.1 relay: read → FORWARD UNCHANGED → then parse framing (llhttp)              │
 │          │                                                                               │
 │          └─ tee: request line, headers (credentials redacted), capped bodies, response,  │
 │             timings, conn id, UA → bounded queue ── full? DROP + count (never blocks)    │
 └──────────────────────────────────────────┬───────────────────────────────────────────────┘
                                            │ writer thread: varint-delimited protobuf Frames
                                            │ Unix socket in a 0700 dir (one-way, in memory only)
                                            ▼
 ┌──────────────────────────── collector (Java 21) ────────────────────────────────────────┐
 │ Receive ─► Parse ─────────► Label ──────────► Classify ─► Detect ─────► Mask ─► Store   │
 │  frames    decode gzip/br/   per-endpoint      MESSAGE_    PII (out)     previews  SQLite│
 │  gap check zstd; JSON,       adapters tag      SENT,       Injection     excerpts  0600  │
 │            multipart, SSE,   each segment:     REPLY_…,    (untrusted)   SHA-256   90-day│
 │            WS; files via     USER_TYPED,       FILE_…,     Exfil (model  (no raw   retent│
 │            sandboxed Tika    ATTACHMENT,       …           output)       text)     -ion  │
 │                              TOOL_RESULT, …                                              │
 │                    coverage counters: drops, drift, unknown endpoints, orphans ──► SQLite│
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

Step by step:

1. **Routing.** Claude fetched the PAC from the proxy when it started. Its network
   stack asks the PAC where `https://claude.ai/api/…/completion` should go. The answer
   is the local proxy, with `DIRECT` as fallback.
2. **CONNECT.** Claude sends `CONNECT claude.ai:443`. The host is in scope, so the
   proxy first opens its own TLS connection to the real claude.ai and verifies it
   strictly. Only then does it reply `200`.
3. **TLS termination.** The proxy completes TLS with Chromium using the leaf
   certificate for `claude.ai`. Chromium accepts it because the local CA is trusted in
   the login Keychain and the name is inside its Name Constraints.
4. **Relay and tee.** Every chunk is forwarded to the other side **unchanged first**,
   and then fed to the HTTP/1.1 framing parser. The proxy records the request
   line and headers, with Cookie/Authorization values removed. It keeps up to 16 MiB
   of request body and 8 MiB of response body (the streamed SSE reply), and records
   the timings and User-Agent. It never interprets bodies.
5. **Queue.** The finished exchange goes into a bounded in-memory queue. If the queue
   is full, the capture is dropped and counted, and Claude's traffic is unaffected.
6. **Socket.** A writer thread sends the capture as a protobuf frame over a private
   Unix socket to the collector.
7. **Parse.** The collector undoes gzip/br/zstd, parses the JSON request, and
   reassembles the SSE reply into complete text blocks.
8. **Label.** The claude.ai completion adapter tags the prompt as `USER_TYPED`,
   attachment text as `ATTACHMENT`, reply text as `MODEL_OUTPUT`, and web-search
   results in the stream as `SERVER_TOOL_RESULT`. Any field it does not recognize is
   still scanned, as `UNKNOWN`, and counted as schema drift.
9. **Classify.** The exchange produces `MESSAGE_SENT` and `REPLY_RECEIVED`, with the org
   and conversation ids from the URL, the model, sizes, and client path `UI`.
10. **Detect.** PII detectors run on the outbound segments. Injection detectors run
    on the attachment and server-tool-result segments. The exfil detector runs on the
    reply text.
11. **Mask.** Each hit becomes a finding that holds only a masked preview, or a
    PII-masked excerpt plus a hash.
12. **Store.** The events and findings are written to SQLite in one transaction.
    The plaintext is released from memory.

## Certificate model

- `llmfw-setup install` creates a **local CA** with critical **X.509 Name Constraints**
  that permit only `claude.ai` and `anthropic.com` (and their subdomains) and exclude
  all IP addresses. Chromium ≥ 112 enforces Name Constraints on locally trusted roots,
  so this CA cannot vouch for any other site even if it were misused.
- It issues **one leaf certificate** with exactly four names: `claude.ai`,
  `*.claude.ai`, `anthropic.com` and `*.anthropic.com` (ECDSA P-256, 397 days).
- It trusts the CA in your **login Keychain** (user trust domain only). macOS asks you to confirm.
- It then **destroys the CA private key**. The key only ever existed in memory and
  was never written to disk. **No signing key remains on the machine.** The proxy can
  only present the leaf it was given, and it cannot mint certificates for anything else.
- The leaf key is stored as a 0600 file in a 0700 directory
  (`~/Library/Application Support/llm-firewall/certs/`). The CA *certificate* (public)
  is stored alongside it for `NODE_EXTRA_CA_CERTS`.
- **Renewal:** run `llmfw-setup renew` once a year. It creates a new CA and leaf,
  swaps the Keychain trust, and restarts the proxy.
- Wildcards cover one label only. A deeper name such as `a.b.claude.ai` is
  blind-tunneled and counted, not decrypted.

## What is and is not logged

**Never written to disk:** raw request or response bodies, prompt text, reply text,
file contents, file names, cookie/authorization header values, or query-string values.

**Logged (SQLite, 0600, 90-day default retention):**

| Record | Contents |
|---|---|
| Event | time, type (`MESSAGE_SENT`, `REPLY_RECEIVED`, `FILE_UPLOADED`, `CONVERSATION_CREATED`, `CONVERSATION_DELETED`, `MODEL_SELECTED`, `OTHER`), client path (`UI`/`CLAUDE_CODE`/`VM`), host, method, **path template** (e.g. `/api/organizations/{org}/chat_conversations/{conv}/completion`), org id, conversation id, model, status, byte sizes, truncation flags, file types (not names), adapter version |
| PII finding | detector, subtype (e.g. `email`, `aws_access_key_id`, `PERSON`), source, location (e.g. `req:$.prompt@120-164`), score, **masked preview only** |
| Injection finding | detector, subtype, source label, location, score, **SHA-256** of the whole source segment, and an **excerpt of at most 200 chars that was PII-masked first** |
| Exfil finding | detector, subtype, location, masked URL (host in clear, query values masked) |
| Coverage counter | per-day counts (see [Coverage counters](#coverage-counters)) |

**Masking rules**
- **PII preview:** `<prefix>…(<N> chars)`. The prefix is the first `min(4, ⌊N/4⌋)`
  characters. A 40-char API key gives `sk-a…(40 chars)`, an SSN gives `12…(11 chars)`,
  and private keys and JWTs get no prefix at all. PII findings have **no hash**,
  because a short value such as an SSN could be recovered from its hash by brute force.
- **Injection excerpt:** a window around the hit. It is **PII-masked before it is
  truncated** (so a secret cut at the edge cannot slip through). Invisible characters
  are rendered as visible `<U+E0041>` tokens (so the log cannot carry a hidden
  payload). It is then capped at 200 characters.
- **Injection hash:** SHA-256 of the full, NFC-normalized segment. The same malicious
  document can then be recognized across conversations without being stored.

**Phase 0 only:** the proxy writes a metadata-only JSONL file
(`~/Library/Logs/llm-firewall/phase0-metadata.jsonl`, 0600). It holds host, method,
path without the query, query *key names*, content types, sizes, UA, timings and
header *names*. It contains no bodies.

## Detectors

| Direction / source | Detectors |
|---|---|
| **Outbound, every source except model output** (`USER_TYPED`, `ATTACHMENT`, `TOOL_RESULT`, `UNKNOWN`) | **PII:** RE2/J regexes for email, phone, US SSN, credit cards (Luhn-checked), API keys/tokens (Anthropic, OpenAI, AWS, GitHub, Slack), private key blocks, JWTs, plus your own custom patterns. A **named-entity model** (ONNX Runtime) for names, addresses, dates of birth and more. OCR of images is phase 2 |
| **Untrusted content entering Claude's context** (`ATTACHMENT`, `TOOL_RESULT`, `SERVER_TOOL_RESULT`, `UNKNOWN`) | **Injection:** heuristic phrase rules (ignore-previous, role override, fake turn markers, tool coercion, secrecy, exfil instructions). **Hidden-content checks:** Unicode tag characters U+E0000–U+E007F, zero-width and bidi controls, CSS/HTML-hidden text, and large base64/encoded blobs. A **classifier** (Meta Prompt Guard 2, ONNX) over overlapping ~512-token windows, keeping the max score and its location |
| **Model output** (`MODEL_OUTPUT`) | **Exfil:** markdown images and links to non-allowlisted domains that carry query data |

"Coming in" means entering Claude's context, not the network direction. Attachments
and local tool results travel *outbound* on the wire, but they are exactly where
injected instructions come from.

**Why injection is never scanned on `USER_TYPED`:** you are the principal. Text you
type is by definition your instruction, not an injection, and scanning it would bury
real findings under false positives (for example, when you discuss prompt injection).
The risk is mislabeling, so adapters use `USER_TYPED` **only when they are certain**.
Anything ambiguous is `UNKNOWN`, which receives *both* PII and injection scans. For
example, Claude Code's system prompt, which includes repo files such as CLAUDE.md, is
labeled `UNKNOWN`.

Custom PII patterns run on RE2/J, which is linear-time. A badly written pattern
therefore cannot hang the collector.

## Failure behavior: fail-open everywhere

| If this fails… | Claude | Logging |
|---|---|---|
| Proxy not running when Claude starts | Works: the PAC cannot be fetched, so Claude connects directly for that whole session | Lost for that session (restart Claude once the proxy is up) |
| Proxy stops while Claude runs | The app works (PAC `; DIRECT`). The engine (b) has no DIRECT fallback, so its requests fail until launchd restarts the proxy (seconds) | Lost while it is down |
| Upstream certificate fails strict verification | Works (the connection is blind-tunneled, and Claude verifies for itself) | That connection is not decrypted (counted) |
| Claude rejects our certificate (e.g. CA removed) | One failed connection, then the host is tunneled for 10 min | Not decrypted (counted) |
| Proxy cannot parse HTTP framing | Works (switches to a raw byte relay) | That connection is not captured (counted) |
| Queue full / collector down / collector slow | Works | Captures dropped (counted, and cross-checked by capture-id gaps) |
| File parser hangs or crashes | Works | No text for that file (the Tika child is killed and recycled) |
| Model file missing | Works | That detector is disabled (counted) |
| claude.ai changes its format | Works | Text still scanned as `UNKNOWN`. Drift counted |

The proxy never waits on the collector, and the collector never talks back to the
proxy.

## Security model of the tool itself

- **No signing key exists.** The CA key is destroyed at setup, and Name Constraints
  limit the CA to two domains anyway.
- **Upstream TLS is strict and cannot be downgraded.** The proxy uses macOS system
  trust plus a hostname check. There is no "insecure" option. If verification fails,
  the proxy steps aside instead of weakening it.
- **Bytes are never modified.** The only bytes the proxy originates are its CONNECT replies.
- **Loopback only.** The proxy refuses to bind any other address, and there is no
  remote interface.
- **Plaintext stays in memory.** It exists only in the proxy, in the kernel socket
  buffer (the socket is in a 0700 directory, with a peer-uid check), and in the
  collector. There are no spool files.
- **Credentials never cross the socket.** Cookie and authorization header values are
  stripped in the proxy.
- **Hardened against hostile content.** Linear-time regexes, JSON depth and size
  limits, decompression caps, Tika in memory- and time-limited child JVMs, and
  libFuzzer + ASan/UBSan on the C++ parsers.
- **Private files.** The database, logs, keys and sockets are all user-only (0600/0700),
  and SQLite uses `secure_delete`.
- **Out of scope:** another process running as *your* user can read your files
  anyway. llm-firewall does not defend against your own account being compromised.

## Coverage counters

Daily counters in the `coverage_counters` table answer the question "what did I miss?":

- **Proxy:** captures dropped because the queue was full or the collector was
  unreachable. Bodies truncated at the cap. Tunnels by reason (not in scope, no
  certificate covers the name, upstream verification failed, TLS breaker open).
  Client TLS failures. HTTP parse errors. Non-CONNECT requests.
- **Collector:**
  - `CAPTURE_ID_GAP`: drops detected independently of the proxy.
  - `UNKNOWN_ENDPOINT` and `SCHEMA_DRIFT`: claude.ai changed or added something.
  - Parse, extraction and detector failures.
  - `SEGMENTS_DEDUPLICATED`.
  - `ORPHAN_REPLY` and `ORPHAN_REQUEST`: a reply without its request, or the reverse.
  - Client paths seen.

The full list is in `collector/.../coverage/CoverageMetric.java`.

## Setup: what it changes on your Mac

> Not yet runnable. This describes the intended behavior of `llmfw-setup install`.

1. **Preflight.** Checks the macOS version, `/Applications/Claude.app`, Java 21, that
   the socket path length is ≤ 103 bytes, and that port 18443 is free. It changes
   nothing if any check fails.
2. **Creates directories** (0700): `~/Library/Application Support/llm-firewall/`
   (with `certs/`, `run/`, `models/` and `bin/` inside) and `~/Library/Logs/llm-firewall/`.
3. **Writes** `llm-firewall.yaml` (from `config/`, and never overwrites your edits).
4. **Certificates:** generates the CA, issues the leaf, writes the leaf key (0600),
   destroys the CA key, writes the CA certificate, and **adds the CA to your login
   Keychain as trusted** (macOS asks you to confirm).
5. **Writes the Claude profile**, a `.mobileconfig` that sets only
   `egressProxyPacUrl` (what `llmfw-setup profile` does today), and opens it. **You
   approve it** in System Settings > General > Device Management, then restart Claude.
6. **Installs two LaunchAgents**, `~/Library/LaunchAgents/dev.llmfirewall.proxy.plist`
   and `dev.llmfirewall.collector.plist`, and loads them (`launchctl bootstrap gui/<uid>`).
7. **Writes `install-manifest.json`**, a list of everything above, which uninstall uses.

It does **not** change system proxy settings, browser settings, any other app's
settings, the system keychain, or anything that needs `sudo`. The only setting of
Claude's it changes is `egressProxyPacUrl`, through the profile you approve. Models (`*.onnx`) are placed in
`models/` separately.

## Uninstall

`llmfw-setup uninstall` reverses exactly what the manifest lists:

1. It unloads and deletes both LaunchAgents.
2. It removes the Claude profile (`dev.llmfirewall.claude-egress-proxy`), or tells you
   to remove it in System Settings > General > Device Management.
3. It **removes the CA's trust setting and the certificate from the Keychain**.
4. It deletes the certificates, the PAC, the socket directory and the manifest.

`--purge` also deletes the database, logs, models and config. After uninstall,
restart Claude. Claude.app itself was never modified.

## Known limits

These cannot be fixed by design:

- **Server-side fetched content that never appears in the stream.** If claude.ai
  fetches a page or queries a connector server-side and does not stream the result
  back, llm-firewall cannot see it. It sees only what is present in the SSE stream.
- **Projects knowledge and memory after upload.** Files are scanned when uploaded.
  Their later server-side use in other conversations is invisible.
- **The Cowork VM** (path c): phase 0 checks that its copy of the PAC reaches the
  proxy. If the VM cannot download the PAC when it starts, it connects directly until
  it next starts, and it has its own CA trust.
- **The Claude in Chrome extension:** this is browser traffic and out of scope.
- **Claude starting before the proxy.** Claude fetches the PAC only at launch, so a
  session started while the proxy is down is not routed at all. The proxy cannot see
  this; Claude's `main.log` shows it.
- **Organization-managed Macs.** Claude reads the proxy keys as a group from one
  managed source. If your organization's profile already sets any of them (or the
  update keys), this profile may be ignored or conflict with it.
- **Format drift.** claude.ai's formats are undocumented. Adapters will break when
  formats change. Text is then still scanned as `UNKNOWN` and the drift is counted,
  but source labels become less precise until the adapter is updated.
- **Truncation.** Bodies above the caps are only partially scanned (flagged on the event).

## Phases

- **Phase 0: validate the routing.** The proxy runs in `metadata_only` mode and
  writes the JSONL metadata log. It checks:
  - that Claude applies `egressProxyPacUrl` (its `main.log` shows
    `[egress-proxy] pinned to PAC script` and `proxy for https://claude.ai resolved … (proxied)`)
  - whether the Claude Code engine and Cowork VM traffic reach the proxy
  - the endpoint map and the field map (collector `--schema-survey`, which records key
    paths and types but never values)
  - how server-side tool results appear in SSE
  - whether HTTP/1.1 causes UI stalls (the 6-connections-per-host limit)
  - the real User-Agent strings
- **Phase 1: analysis.** The collector runs parse, label, classify, detect, mask and
  store, along with retention and coverage.
- **Phase 2: extensions.**
  - OCR for images (Tess4J).
  - Event correlation: untrusted content in, followed by a suspicious link out.
  - A dashboard over SQLite.
  - HTTP/2 via nghttp2, if phase 0 shows stalls.
  - Web support: a system PAC, Chrome/Firefox profiles with HTTP/3 off, and Safari validation.

## Repository layout

```
llm-firewall/
  README.md                 this file: how everything works
  .gitignore
  config/
    llm-firewall.yaml       example config (ports, socket, scope, caps, queue, retention, allowlist, custom PII)
    claude.pac              PAC template the proxy fills in and serves at /proxy.pac
  proto/
    capture.proto           proxy→collector wire contract + framing rules
  proxy/                    C++20 / CMake: the proxy (llmfw-proxy) and the setup CLI (llmfw-setup)
    CMakeLists.txt, vcpkg.json
    cmake/                  pac_template.hpp.in (embeds config/claude.pac)
    include/llmfw/, src/    implementation
    tests/                  GoogleTest unit and integration tests
```

The collector (Java 21), TLS decryption and the LaunchAgent templates are added to the
repository when they are built.

## Build and test

The proxy in `proxy/` builds and runs in `metadata_only` mode: it blind-tunnels every
CONNECT (nothing is decrypted yet) and logs one metadata record per tunnel.
`llmfw-setup profile` writes the configuration profile that points Claude at it.
Installing (certificates, Keychain trust, LaunchAgents) and the collector are not built yet.

Prerequisites (macOS, Apple Clang 15 or newer, C++20):

```sh
brew install cmake ninja boost yaml-cpp protobuf googletest
# tested with CMake 4.4, Ninja 1.13, Boost 1.92, yaml-cpp 0.9, protobuf 36.2, GoogleTest 1.18
```

Build and run the tests:

```sh
cmake -S proxy -B proxy/build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="$(brew --prefix)"
cmake --build proxy/build
ctest --test-dir proxy/build --output-on-failure
```

`CMAKE_PREFIX_PATH` makes CMake prefer Homebrew's packages. Without it, another
installation on the search path (such as Miniconda's older GoogleTest) can be found
first and fail to link.

With AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S proxy -B proxy/build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DLLMFW_SANITIZE=ON -DCMAKE_PREFIX_PATH="$(brew --prefix)"
cmake --build proxy/build-asan
ctest --test-dir proxy/build-asan --output-on-failure
```

### Running the proxy

```sh
proxy/build/llmfw-proxy --config config/llm-firewall.yaml
```

It listens on `127.0.0.1:18443`, logs operational lines (hosts, counts, errors) to
stderr, and appends one JSON line per closed tunnel to
`~/Library/Logs/llm-firewall/phase0-metadata.jsonl` (mode 0600). To try it without
Claude, send a request through it:

```sh
curl -x http://127.0.0.1:18443 https://example.com/
```

Ctrl-C or SIGTERM shuts it down: open tunnels are closed and still logged, and a
counter summary is printed. Exit codes: 0 clean, 1 unexpected error, 2 bad command
line or configuration, 3 the metadata log cannot be opened, 4 the port cannot be bound.

### Phase 0: route Claude through the proxy

This checks that Claude applies `egressProxyPacUrl`, and which hosts each traffic path
connects to. It needs Claude Desktop 1.44121.1 or later.

1. Write the profile:
   `proxy/build/llmfw-setup profile --config config/llm-firewall.yaml`.
   It goes to `~/Library/Application Support/llm-firewall/llm-firewall-claude-proxy.mobileconfig`
   and sets only `egressProxyPacUrl = http://127.0.0.1:18443/proxy.pac`.
2. Install it: `open` the file, then approve it in System Settings > General > Device
   Management. Check that `/Library/Managed Preferences/$USER/com.anthropic.claudefordesktop.plist`
   now exists.
3. Start the proxy and leave it running:
   `proxy/build/llmfw-proxy --config config/llm-firewall.yaml`
4. Quit Claude (Cmd-Q) and start it normally. Claude reads the setting at launch.
5. Check that it took effect:
   - the proxy's stderr shows `served PAC conn=…`, then `tunnel open … host=claude.ai:443 reason=scoped_no_cert`;
   - `grep -E "egress-proxy|proxy for https://claude.ai" ~/Library/Logs/Claude/main.log`
     shows `pinned to PAC script` and `(proxied)`.
6. Start a Chat, a Code session and a Cowork task. The engine's and the VM's
   connections appear as further tunnels; `~/Library/Logs/Claude/cowork_vm_node.log`
   shows `[VM:start] guest egress pinned to PAC script`.
7. Quit Claude, then stop the proxy (Ctrl-C). The metadata log has one record per tunnel.

To stop routing Claude through the proxy, remove the profile in System Settings >
General > Device Management and restart Claude.
