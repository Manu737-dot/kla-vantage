# kenya-llm-latency

A small measurement tool that runs on an Ubuntu laptop for a few days and records,
from a real home internet connection in Kenya, how long it takes to reach the
major LLM APIs, and *where* that time goes.

It answers three questions with data:

1. **Network:** for each LLM API, how long do DNS, TCP connect, TLS handshake and
   the server's first byte take on a fresh connection, and how does that compare
   with cloud regions in Africa, Europe and the US and with sites hosted in Kenya?
2. **AI reply** *(optional, needs free API keys)*: how long until the first word
   of a model's answer appears?
3. **Fixes:** how much do connection reuse, streaming, a smaller model or a
   nearer region actually help?

Everything is stored in an append-only SQLite file and can be exported to CSV.
`kla analyze` writes a markdown report (numbers only) and article-ready PNG charts.

---

## Quick start

```bash
# 1. install uv (Python package manager) if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. get the code and its dependencies (no sudo needed; pycurl ships as a wheel)
git clone https://github.com/<you>/kenya-llm-latency.git
cd kenya-llm-latency
uv sync

# 3. one manual run of each part, to see that it works
uv run kla probe -v          # Part 1: one request to every target, prints a table
uv run kla trace             # route to every LLM host (mtr)
uv run kla status

# 4. optional: free-tier API keys for Part 2 (OpenAI is the one paid, opt-in, $1-capped key)
cp .env.example .env         # then fill in the keys you have

# 5. collect for 3-5 days
uv run kla start             # installs systemd *user* timers (no sudo)

# 6. look at the results any time
uv run kla analyze           # reports/latest/report.md + *.png
uv run kla export            # data/export/*.csv
```

Requirements: Ubuntu 22.04+ (tested on 24.04), Python 3.12+, NetworkManager
(`nmcli`), `ping`, `mtr` (`sudo apt install mtr-tiny` if missing).

## Commands

| command | what it does |
|---|---|
| `kla probe [-v]` | Part 1: one network-context snapshot + one fresh request to each target |
| `kla trace` | `mtr` route to each LLM host, masked and summarised |
| `kla ai` | Part 2: one streamed call per provider that has a key and is due |
| `kla experiment reuse [--n 20] [--targets openai,groq]` | fresh vs reused connection |
| `kla experiment stream --provider groq [--n 5]` | streaming vs non-streaming |
| `kla experiment model-size --provider gemini [--n 5]` | small vs larger free model |
| `kla experiment region` | Africa vs Europe vs US cloud regions (from stored data) |
| `kla analyze [--since-days 3] [--include-vpn] [--include-mixed] [--include-offline]` | report.md + charts in `reports/latest/` |
| `kla analyze --network "Safaricom 5G"` / `--each-network` | the same report for one network / one per network in `reports/networks/` |
| `kla networks` | networks seen, labels, runs that changed network mid-run |
| `kla label NAME` | name the router you are connected to now |
| `kla label NAME --from "2026-10-22 10:06" --to "2026-10-22 11:10"` | name a period (EAT); also for runs made before fingerprints existed |
| `kla label NAME --router a1b2c3` / `kla label --clear ...` | name another router seen before / remove a name |
| `kla export [--tables probes,runs]` | CSV per table in `data/export/` |
| `kla start [--print]` / `kla stop` | install + enable / disable the timers |
| `kla status` | timers, last runs, counts, failures, gaps, setup checks |
| `kla vantage pull` | import the GitHub runner's results into `data/vantage.sqlite3` |
| `kla vantage run --data-dir DIR` | the runner's measurement (GitHub Actions only) |

Global options: `--config path/to/config.yaml`, `--db other.sqlite3` (e.g. for a dry run).

---

## Method

### What one probe measures

Every probe opens a **brand-new connection** (no connection reuse, no TLS session
resumption, a new curl handle each time), sends one unauthenticated `GET`, and
reads libcurl's timestamps:

```
start ── DNS ── TCP connect ── TLS handshake ── request sent ── first byte ── last byte
          │         │               │                               │             │
       dns_ms    tcp_ms          tls_ms                          ttfb_ms     transfer_ms
```

| column | meaning |
|---|---|
| `dns_direct_ms` | DNS lookup sent straight to the upstream resolver (see below) |
| `dns_system_ms` | DNS through the normal system path (systemd-resolved, may be cached) |
| `tcp_ms` | TCP connect ≈ **one network round trip** to the server's front door |
| `tls_ms` | TLS handshake (TLS 1.3 ≈ one more round trip + crypto) |
| `ttfb_ms` | "server wait": request sent → first response byte |
| `transfer_ms` | first → last byte (tiny here; replies are < 5 KB) |
| `total_ms` | `dns_direct_ms` + everything after it: the cost of a *first* request |

Also recorded per request: HTTP status (401/403/404 are expected and fine; we
time the network, not the API), HTTP version, TLS version and cipher, ALPN,
the server IP, response size, the error type on failure (`timeout_connect`,
`timeout_tls`, `dns_failure`, …), and the **CDN edge** that answered, taken
from headers such as `cf-ray: …-MBA` (Cloudflare, Mombasa) or
`x-amz-cf-pop: NBO50` (CloudFront, Nairobi).

Implementation notes:

- **HTTP/1.1** is used by default (`probe.http_version`). It is what the official
  Python SDKs (built on httpx) use unless HTTP/2 is switched on. It also avoids a
  client bug: in testing, the libcurl 8.22 bundled with pycurl 7.48 added a stall
  of about 1 s to small HTTP/2 replies that the system `curl` 8.5 did not show, which
  would have polluted the timings. HTTP/3 (QUIC) is not used, but whether the
  server advertises it is recorded (`alt_svc_h3`).
- A TCP or TLS step of ≥ 1 s on a path whose usual round trip is ~10-250 ms is
  counted as **likely packet loss** (Linux resends a lost packet after about 1 s).
  The report lists these separately. This is an inference from timing, not a
  packet capture.
- IPv4 only: this connection had no IPv6 when the tool was built (set
  `probe.ip_version` in the config if yours does).
- The order of targets is shuffled every run, so no provider is always first.
- A lock file stops the probe, traceroute and AI jobs from running at the same
  moment and disturbing each other.

### Ping vs real connection

Right after each probe, the tool sends a light ping (exactly 3 packets,
`ping -c 3 -i 0.2 -W 1`; a host that never answers costs about 1.4 s) to **the same IP**
the probe just connected to, and stores it in the `pings` table (linked to the run and target). Ping (ICMP) can be answered by an edge
server or router nearby while the real TCP connection is handled far away;
`kla analyze` puts the two side by side ("Ping vs real connection" table and
`ping_vs_tcp.png`). Hosts that block ping are stored as `no_reply`: missing
data, not a failed probe. The ping runs after the probe finishes, so it does not
change the probe's own measurements or their order.

**Ping loss, and a fix on 22 Oct 2026.** Up to tool version 0.1.0 (pings saved
from 08:31 to about 19:30 EAT on 22 Oct) the ping also had a `-w 3` deadline. With
that, `ping` keeps sending until it has 3 *replies*, so slow or lossy hosts got 4-15
packets and the stored `sent` and `loss_pct` overstate loss (a host 250 ms away
showed ~25% "loss" while every packet came back). Since 0.2.0 exactly 3 packets
are sent. Old rows are not edited. `kla analyze` never uses the stored `loss_pct`:
it counts loss as replies missing out of the packets meant to be sent, i.e. out of 3
for runs whose `runs.tool_version` is 0.1.0, and only for hosts that answer ping
(a host that blocks ping is missing data, not loss). Ping timings (min, median,
max) were always taken from the replies and are unaffected.

### DNS and caching (the deliberate choice)

Ubuntu's `systemd-resolved` caches answers on the laptop, so "how long did DNS
take" usually says nothing about the network. The tool therefore measures DNS
**twice**:

1. **direct**: a query sent with `dnspython` straight to the resolver that
   systemd-resolved forwards to (normally the home router, read from
   `/run/systemd/resolve/resolv.conf`), skipping the laptop's cache. This
   runs **first**, so step 2 can't warm the router's cache for it.
2. **system**: a normal `getaddrinfo()` call, which is what apps experience
   (often instant because of the cache).

The address from the direct lookup is then **pinned** into curl
(`CURLOPT_RESOLVE`), so the TCP/TLS/TTFB numbers contain no DNS time at all.
The answer's TTL is stored too. Limitation: the router (and the ISP resolver
behind it) has its own cache that the tool can't bypass. A "direct" lookup is
therefore "uncached on this laptop", not "uncached anywhere".

### Targets and how they were chosen

All targets live in [`config/config.yaml`](config/config.yaml), each with the
official documentation page that confirms the hostname (`source`). Checked on
2026-10-21.

- **LLM APIs:** OpenAI, Anthropic, Google Gemini, Mistral, Groq, OpenRouter,
  DeepSeek, Cohere, xAI. Each URL was picked to return a tiny 401/403 reply.
- **Cloud regions (no auth):**
  - AWS DynamoDB regional endpoints (`af-south-1` Cape Town, `eu-west-1`, `us-east-1`)
  - Azure Speech regional endpoints (`southafricanorth` Johannesburg, `westeurope`, `eastus`)
  - Google Cloud Storage **regional endpoints** (`*.rep.googleapis.com`: `africa-south1`
    Johannesburg, `europe-west1`, `us-central1`). Google documents that traffic to these is
    "processed and TLS terminated within the specified region". Ordinary
    `*.googleapis.com` hosts are anycast and would not measure the region.
- **AI cloud endpoints, network only (added 23 Oct 2026, group `ai-cloud`):**
  no data before that date. Requests carry no key, so nothing is billed; each
  answers with a tiny error, which is enough to time the connection.
  - Cloudflare Workers AI: `api.cloudflare.com`, the host its
    [REST API](https://developers.cloudflare.com/workers-ai/get-started/rest-api/)
    uses (`/client/v4/accounts/{id}/ai/run/{model}`). Anycast.
  - AWS Bedrock runtime in Cape Town: `bedrock-runtime.af-south-1.amazonaws.com`,
    listed as supported on AWS's
    [Regional availability by endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/endpoints-region-availability.html)
    page. (The older general endpoints table doesn't list it yet.) AWS's model
    tables show Cape Town offering models only through *global* cross-Region
    inference, so a request enters in Cape Town but may be processed in another
    Region.
  - Azure, South Africa North: `southafricanorth.api.cognitive.microsoft.com`.
    Azure OpenAI has no shared hostname to probe, because each resource gets its
    own `<name>.openai.azure.com`. Microsoft lists this host as the regional
    endpoint for Azure AI services in that region, which
    [its docs](https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-custom-subdomains)
    describe as "common for all customers in a specific Azure region".
  - They get a group of their own so the `llm`, `cloud` and `local` medians
    before and after 23 Oct stay comparable.
- **Local baselines:** `www.google.com/generate_204` (Google edge in Kenya),
  KENET (Kenya Education Network) and Cloudflare `1.1.1.1`. Each answered in
  under 15 ms of round-trip time when tested, so they separate *local* delay
  from *international* delay.

**Anycast caveat:** most LLM APIs sit behind a CDN (often Cloudflare). Their TCP
and TLS handshakes finish at the **nearest edge** (possibly Mombasa or
Nairobi), while `ttfb_ms` includes the trip from that edge to the real
servers, usually in the US. So for LLM hosts, `tcp_ms` measures *distance to
the CDN* and `ttfb_ms` contains *distance to the model*.

### Network context recorded with every run

| field | how |
|---|---|
| UTC and EAT timestamps, hour of day, weekday | system clock (NTP-synced; `kla status` checks) |
| ISP ASN and name | public IP from `https://1.1.1.1/cdn-cgi/trace`, then RIPEstat `prefix-overview` (Team Cymru DNS as fallback). **Only the ASN and name are stored; the IP is held in memory and discarded.** |
| connection type | `nmcli`: `wifi`, `hotspot` (metered Wi-Fi or a name listed in `context.hotspot_ssids`), `usb-tether`, `ethernet`, `mobile-modem`, `vpn` |
| Wi-Fi signal | `nmcli` signal %, frequency/band, link rate; dBm from `/proc/net/wireless`; Wi-Fi power-save setting |
| router ping | 5 pings to the default gateway: median, jitter (mdev), loss. High values = a Wi-Fi/home problem, not the internet |
| VPN | whether traffic leaves through a tunnel: a known VPN name, any tun/WireGuard device (from `/sys/class/net`), or `warp-cli status` saying Cloudflare WARP is connected. VPN runs are excluded from analysis by default |
| network check, start and end | router fingerprint and VPN state, stored in `net_checks` (see Networks) |
| power and sleep | on AC or battery; boot id; total time asleep since boot |

Free "what is my IP" APIs (ipinfo, ipapi) rate-limited this connection on the
first request, probably because many customers share one public IP (carrier-grade NAT).
That's why RIPEstat and Team Cymru are used instead.

### Gaps (power cuts and sleep are normal)

Each probe run compares itself with the previous one. If they are more than 25
minutes apart, a row is written to `gaps` with a cause:

- `restart`: the boot id changed (power cut, shutdown or crash)
- `sleep`: the kernel's time-asleep counter grew by at least half the gap
- `missed`: the laptop was awake but nothing ran (timer stopped, failed run)

The first run after a gap is flagged (`runs.after_gap`). systemd's
`Persistent=true` runs a missed job as soon as the laptop wakes, and the probe
waits up to 60 s for the network to come back first.

### Routes (hourly)

`mtr --json -z -b -c 5` to each LLM host (resolved IP), which gives per-hop
loss, best, average and worst RTT, and the ASN (via Team Cymru).
Before saving:

- private hops (192.168.x, 10.x, 172.16-31.x, CGNAT 100.64/10) become `private-hop`
- any hop whose IP *or hostname* contains your public IP (also in dashed or
  reversed form, e.g. `41-90-12-34.isp.ke`) becomes `your-connection`
- the local hostname mtr reports is never stored

Public router hostnames are kept, because they reveal cities: `…-nbo…` Nairobi,
`…-mba…` Mombasa, `mrslfr…` Marseille. These **city hints are guesses from naming
conventions** and are labelled as unverified. The summary also stores the AS
path (e.g. `Tawala > SEACOM > Cloudflare`) and the **biggest RTT jump**
between consecutive hops, which usually marks a submarine-cable crossing.

### Part 2: AI time to first token (optional)

Only runs for providers with a key in `.env`; others are skipped. Free tiers
only, enforced in code, with one exception: OpenAI, which is paid, opt-in and
capped at $1.00 in total (see below).

| provider | small model | larger model | where the price was checked |
|---|---|---|---|
| Google Gemini | `gemini-3.5-flash-lite` | `gemini-3.8-flash` | [pricing page](https://ai.google.dev/gemini-api/docs/pricing): both "Free of charge" on the free tier |
| OpenRouter | `nvidia/nemotron-3.5-lightning:free` | `nvidia/nemotron-3-ultra-550b-a55b:free` | `:free` suffix **and** price 0 in OpenRouter's live endpoint data, checked before every call |
| Groq | `openai/gpt-oss-20b` | `openai/gpt-oss-120b` | [free plan rate-limit table](https://console.groq.com/docs/rate-limits) (30 req/min, 1,000/day) |
| OpenAI (**paid**) | `gpt-5-nano` | – | [pricing page](https://developers.openai.com/api/docs/pricing), checked 23 Oct 2026: $0.05 per 1M input tokens, $0.40 per 1M output, the cheapest listed |

- A model not on the verified free list is **refused**, unless its provider is
  a paid one you opted into (below) or you set `ai.allow_paid: true`. If the free
  status can't be verified (e.g. OpenRouter is unreachable), the call is refused.
- A fixed tiny prompt (`Reply with exactly one word: hello`) with streaming, and a
  token cap of 32 (64 for OpenAI and 128 for Groq, because hidden reasoning
  tokens count against the cap).
- Rolling 24-hour budgets per provider (Gemini 15, OpenRouter 40 of its 50/day
  free limit, Groq 100, OpenAI 30), a minimum gap between scheduled calls
  (Gemini every 2 h, the others every 1 h), and a cool-down after any HTTP 429
  (1 h for OpenRouter and OpenAI, 2 h for Groq, 4 h for Gemini).
- **OpenRouter model change, 23 Oct 2026.** Gemma 4 (served by Google AI
  Studio) was rate-limited upstream on all 4 scheduled calls on 22–23 Oct, so it
  never produced a measurement. Both Nemotron models run on NVIDIA's own servers
  and answered in a test that day. Their hidden reasoning is switched off
  (`reasoning: {enabled: false}`), because with it on the first visible word took
  about 9.5 s instead of 2 s.
- Google does not publish the free-tier daily quotas (they are shown per
  project in AI Studio), hence the conservative Gemini budget. **If your AI Studio
  project has billing enabled, Gemini calls are billed.** Use a project without
  billing. Google's free tier may also use prompts to improve its products. The
  prompt here is a fixed "hello", nothing personal.
- Keys are sent only in headers (never in URLs), never printed, and scrubbed from
  anything stored (e.g. error messages).

**OpenAI: the one paid provider (opt-in, $1.00 hard cap, added 23 Oct 2026).**

- **When it runs:** only while `opt_in: true` is set under
  `ai.providers.openai` in `config.yaml` **and** `OPENAI_API_KEY` is in `.env`.
  Remove the key or set `opt_in: false` to stop it.
- **Settings:** hourly, at most 30 calls in any 24 h, and only the model priced
  in `paid_models` (`gpt-5-nano`). Its reasoning effort is set to "minimal", and
  the 64-token cap also limits hidden reasoning.
- **Pricing each call:** the cost goes into the `ai_spend` table the moment the
  call ends, before the run is saved, so a crash can't hide it. The price comes
  from the token counts OpenAI reports at the end of the stream. If it reports
  none, the call is counted at the most it could have cost: every prompt byte as
  a token, plus the full 64-token output. Requests OpenAI rejects (HTTP 4xx)
  generate nothing and count as $0. So does a call that never finished
  connecting (no TLS handshake, no HTTP reply), because the request only goes
  out after the handshake (basis `not_sent`).
- **No network, no calls:** if the laptop has no network route at all (after
  waiting up to 60 s, as a probe does), the AI run makes no calls and saves
  nothing, for every provider. No free quota, spend or schedule slot is used.
  This was added on 23 Oct 2026. Before that, one AI run during a power cut
  tried anyway, and its OpenAI attempt sits in `ai_spend` at its worst
  case ($0.0000305), even though nothing was sent. The row is kept, because the
  ledger is append-only, and it only makes the cap slightly stricter.
- **The cap:** before any call, `kla` adds up `ai_spend` and refuses if the
  calls about to be made could, at their worst case, push the total past
  `spend_cap_usd` ($1.00). Scheduled runs and experiments both stop there by
  themselves. One call costs about $0.000003, so $1 lasts for years at an hourly
  rate. The cap is there to catch mistakes.
- **Dry runs count too:** they spend real money, so `ai_spend` always lives in
  the main database (`storage.spend_db_path`), even when `--db` points
  elsewhere. `ai_spend` is append-only like the rest.
- `kla status` shows the spend so far, for example `$0.000003 of $1.00 cap spent
  over 1 call(s)`.
- A second guard on OpenAI's side is worth having too: keep only a small prepaid
  credit balance on the account, with auto-recharge off.

Recorded: `ttfb_ms` (first HTTP byte), `ttft_any_ms` (first token of any kind,
including streamed reasoning), `ttft_visible_ms` (first text a user would see),
`total_ms`, output size and finish reason, plus the same connection phases as Part 1.

**First token and total on one clock, a fix on 22 Oct 2026.** From tool version
0.3.0 the two first-token times and `total_ms` come from one clock that starts
the moment curl starts the request and stops when curl returns, so a first token
can never land after the total. Before that, the first-token clock started a
little earlier, while curl was still being set up (about 24 ms on the first
request of a run, under 2 ms after that), and `total_ms` came from curl's own
clock, which stops a fraction of a millisecond before the last data reaches the
program. A one-word answer could then show its first token *after* the total
(Gemini, 22 Oct 22:17: 1,589 ms vs 1,580 ms). Stored rows are not changed:
`kla analyze` leaves out the first-token times of AI calls made before 0.3.0
and says how many. Their success/failure and total still count, because curl's
total is within a few ms of the new one. The connection phases (`dns_ms` to
`ttfb_ms`) come from curl in both versions.

### Part 3: fix experiments

Run on demand. Each alternates its two arms (A, B, A, B …) so changing network
conditions hit both equally, saves raw samples, and writes a before/after table
(median, p95, % change) to `reports/experiments/`.

- `reuse`: 20 fresh vs 20 reused-connection requests per LLM host. Reuse is
  *verified* (libcurl reports whether a new connection was opened), not assumed.
- `stream`: non-streaming vs streaming time to the first visible word.
- `model-size`: small vs larger free model, both streaming.
- `region`: Africa vs Europe vs US per cloud provider, from Part 1 data (no new traffic).

AI experiments check the remaining free budget before they start and refuse if
they would exceed it.

### Near/far switches: DNS steering or anycast?

Some providers are reached nearby (Mombasa, ~10 ms TCP connect) at one moment and
far away (Europe, ~200 ms) at another. `kla analyze` explains each such target
using data already collected (no extra traffic):

- each probe is **near** (< 100 ms TCP connect) or **far** (≥ 100 ms). Handshakes
  ≥ 1 s are skipped (lost packets);
- if any IP address was seen in **both** states, DNS did not cause the switch: the
  same address was near at one moment and far at another (**anycast**). If the far
  and near addresses never overlap, it is **DNS steering**;
- for same-IP switches, each hourly traceroute is paired with the probe closest
  in time (preferring the same IP). If ping to the IP stayed local and the network
  path stayed the same while TCP went far, the packets entered the provider's
  network nearby and the extra time was added **inside** the provider's network.
  If ping saw at least half of the extra delay, or the path changed, it is a
  **route change**;
- it also flags targets that flip back and forth, and targets whose TLS
  handshake stays slow even when TCP is answered nearby (the encrypted session is
  set up far away).

This is an inference from timing, not a packet capture. Ping (ICMP) can be
answered by a different machine than the one handling TCP; that difference is
exactly what the check uses, but it is still indirect evidence.

### Networks: which router was each run on?

The study can move between networks (Tawala, a Safaricom 5G router,
Safaricom fibre). The 5G router and the fibre share one ISP and one ASN, so the
ASN cannot tell them apart. The router can.

**Fingerprint.** Every run checks its network twice, at the start and at the end,
and stores each check in `net_checks` (linked to the run; nothing is added to the
existing tables). A check records:

- the router's **fingerprint**: a salted hash of the router's hardware (MAC)
  address, read from the laptop's neighbour table (`ip neigh`). Every router has its own
  MAC, so two routers get two fingerprints even when both use 192.168.1.1 and the same ISP.
  The MAC itself is never stored, because MACs can be looked up in public Wi-Fi maps to
  find a location. The salt is a random secret in `data/router-salt` (git-ignored), so the
  database alone can't be used to recover the MAC. If that file is lost, routers get new
  fingerprints and need labelling again.
- the router's local address (only if it is private, like 192.168.0.1);
- whether a VPN carried the traffic, which one, and Cloudflare WARP's own status.

The physical router is found from the main routing table, so it is still seen
when a VPN sits on top.

**Names.** `kla label` stores names in `net_labels`. Nothing is ever edited: a newer
label wins over an older one, and `--clear` adds a "no name here" row. Each run's
network is the first of:

1. a **period label** covering the run (`--from/--to`);
2. a **router label** for its fingerprint (`kla label NAME` while connected, or `--router`);
3. the fingerprint itself, unnamed (`router a1b2c3`);
4. for runs made before fingerprints existed: the router's local address, which old
   probe runs stored as their DNS server. Traceroute runs borrow it from the nearest
   probe run (within 20 minutes). If exactly one fingerprinted router was later seen at
   that address, the old runs join it.

**Changed mid-run.** If a run's start and end disagree (a different router or
network name, or a VPN switching on or off), it measured two networks at once.
`kla networks`, `kla status` and the report list it with the reason, and comparisons
leave it out unless `--include-mixed` is given. A run where Wi-Fi was simply lost is
not a change: it is outage data and stays in.

**No network at all.** A run that starts with no network route, even after
waiting 60 s (Wi-Fi switched off, or the router gone in a power cut), measures
the laptop being offline, not the ISP or the providers. Its runs are marked with
connection type `none`, are left out of the analysis unless `--include-offline`
is given, and are listed in the report's coverage section with their times. A
dead *internet* behind a working router is different: that is the ISP failing,
and it stays in.

Limitation: the network is checked only at the start and end of a run. A VPN that
switches on and off again within one run (20 s to a few minutes) is not caught.

### Comparison vantage point: a GitHub runner (added 25 Oct 2026)

To separate network time from provider time, the same measurements also run
hourly from a GitHub-hosted runner, a VM in an Azure datacentre
(`.github/workflows/vantage.yml`, `src/kla/vantage.py`). From there the network
part is small, so what remains is mostly the provider's own time.

- **Same code and settings.** The runner checks out the same commit, installs from
  the same `uv.lock` (Python 3.12.12, pycurl 7.48.0 with its bundled libcurl), and
  calls the laptop's own functions: `probe.probe_target` for the 9 LLM API hosts
  (fresh HTTP/1.1 connection; DNS, TCP, TLS, server wait, total; Cloudflare
  location from `cf-ray`) and `ai.call_model` for the AI calls (same models,
  prompt, streaming and one-clock first-token timing). `config/vantage.yaml` holds
  the few differences. No ping or `mtr`: GitHub runners block ICMP.
- **When.** At :45 every hour (GitHub often starts a few minutes late), 10-15 min
  after the laptop's AI run and alongside its :45 probe round. Groq and OpenAI
  every hour; Gemini and OpenRouter every 2 h on odd EAT hours, because free
  daily quotas belong to the API key and the runner uses the laptop's keys
  (OpenRouter: 24 laptop + 12 runner calls of its 50 a day).
- **Where the runner was**, per run (`vantage_context`): its public IP (GitHub's
  Azure address, not the laptop's), ASN and city/country from RIPEstat, the
  Cloudflare location that answered it, and the Azure region and VM size from
  Azure's instance metadata service when the runner allows it.
- **Results.** One SQLite file per run, with the laptop's tables plus
  `vantage_context`, committed to the `vantage-data` branch (never `main`) of the
  public repo the runner works in (`vantage.repo_url` in `config/vantage.yaml`).
  `kla vantage pull` imports new files into `data/vantage.sqlite3`, every row
  labelled `vantage = us-runner`. The Kenya database is never written to.
- **Spend.** OpenAI calls from the runner have their own ledger
  (`ledger/spend.sqlite3` on `vantage-data`) and a hard **$0.25** cap
  (`vantage.HARD_CAP_USD`, which the config can lower but not raise). With no
  ledger, no paid call is made. The laptop's $1.00 cap is separate.
- **Keys** come from GitHub Actions secrets, only in the measuring step.
- **End date.** The first run after 31 Oct 2026 23:59 EAT switches the workflow
  off without measuring. Until then about 165 runs, about 330 Actions minutes.

### Analysis

`kla analyze` reports, per target and phase, `n`, p50 (median), p95, p99 and the
failure rate, followed by patterns by hour of day (EAT), connection type, cloud
region, CDN edge, routes and AI timing. Percentiles that rest on too few samples
are marked `*` (p95 needs ≥ 40 samples, p99 ≥ 200), because with fewer samples
they are really just "the slowest one or two requests". Failure rate counts
requests that got **no HTTP answer at all**.

The report starts with a **Networks** section: every network with its runs, period,
ISP and how it was identified, the labels, the runs left out because the network
changed mid-run, and (when there is more than one network) a table of the same
targets on each network. The rest of the report combines all networks unless
`--network NAME` is given; `--each-network` writes one full report per network. The
near/far switch check always runs inside each network, because moving to another
network is not a switch.

Charts (`reports/latest/*.png`): where the time goes (stacked medians), spread
per LLM API (box plot), time of day vs router ping, cloud region dot plot,
connection type, and AI first-token times. Colours come from a colour-blind-checked
palette, and every chart has a legend or direct labels.

---

## Keep it running for 3-5 days

`kla status` checks all of these. Nothing below is applied automatically.

**1. Run after reboots and while logged out (no sudo):**
```bash
loginctl enable-linger "$USER"
```
Without this, user timers stop when you log out, and after a power cut nothing
runs until you log in again.

**2. Don't sleep on AC power.** Check GNOME:
```bash
gsettings get org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type   # want 'nothing'
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing'
```

**3. Keep running with the lid closed while on AC (needs sudo):**
```bash
sudo mkdir -p /etc/systemd/logind.conf.d
printf '[Login]\nHandleLidSwitchExternalPower=ignore\n' | \
  sudo tee /etc/systemd/logind.conf.d/kla-lid.conf
# takes effect after a reboot (restarting systemd-logind can end your desktop session)
```
On battery, closing the lid still suspends as usual. To undo: `sudo rm /etc/systemd/logind.conf.d/kla-lid.conf`.

**4. Clock in sync:** `timedatectl show -p NTPSynchronized` should say `yes`.

**5. VPN off:** a VPN changes the route completely. Runs made through a VPN are
flagged and excluded from analysis by default, and `kla status` prints a large
warning while one is on. Cloudflare WARP in "Always On" mode can switch itself on
after a network change; `warp-cli disconnect` turns it off.

## Privacy and being a good citizen

- Never stored: your public IP, the Wi-Fi network name, your router's MAC address
  (only a salted hash of it), your laptop's hostname, API keys, response bodies.
- One request per target per 15 minutes (≈ 96 a day per host), unauthenticated, with an
  honest `User-Agent` that names the tool. No load testing.
- AI calls stay well inside the published free limits. The one paid provider
  (OpenAI, opt-in) has a hard $1.00 cap on its total spend.
- `.env`, `data/` and `reports/` are git-ignored. Review exported data before
  publishing it.

## Limitations

- **One home, one ISP, one city.** The results describe this connection
  (Machakos, Wi-Fi, a single ISP). They show what a Kenyan user *can* experience,
  not a national average.
- **Not a browser.** curl over HTTP/2 with a fresh connection is a worst-case
  "first request". Real apps reuse connections (see the `reuse` experiment),
  may use HTTP/3, and add their own processing.
- **401 is not inference.** Part 1 measures the network path and the API's front
  door, not model speed. Part 2 measures real (tiny) generations, mostly on free
  tiers, which may be slower or more variable than paid tiers (OpenAI is the one
  paid provider).
- **Anycast and CDNs.** For LLM hosts, TCP and TLS measure distance to the nearest
  CDN edge, not to the model servers (see Method).
- **DNS caches upstream** (router and ISP) can't be bypassed.
- **Time-of-day patterns need several days.** With 3-5 days, each hour has only
  12-20 runs. Treat hourly differences under ~20% as noise.
- **City hints from router names are guesses.** RTT jumps are stronger evidence.
- **Gaps.** Runs missed during power cuts or sleep are recorded as gaps rather than
  hidden. Coverage is in the report.
- **Wi-Fi power saving** (enabled by default on many laptops) can add a few ms to
  every packet. It is recorded but not changed.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest            # network is fully mocked; a guard fails any test that tries to connect
```

Code map (`src/kla/`): `http.py` (pycurl timing), `dnsprobe.py`, `context.py`,
`probe.py` (Part 1), `pinger.py`, `trace.py`, `ai.py` (Part 2, incl. the paid spend
cap), `experiments.py` (Part 3), `analyze.py`, `steering.py`, `netcheck.py` + `networks.py` (router fingerprints, labels),
`stats.py`, `gaps.py`, `db.py` (append-only SQLite), `privacy.py`,
`systemd.py`, `status.py`, `export.py`, `cli.py`.

License: MIT.
