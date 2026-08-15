---
name: hunt-dns-tunnel
description: "Hunt for DNS tunneling in Suricata eve.json. Detects two archetypes - (1) TXT base64 file exfiltration with sequential chunked payloads, (2) dnscat2-style C2 with hex-encoded QNAME subdomain labels and multi-type channel rotation (MX/TXT/CNAME). Reconstructs and decodes exfiltrated payloads or extracts raw session bytes, looks up flow sizes from event_type:flow, and prints a structured report with an event table. Use when asked to find suspicious DNS, detect DNS tunneling, or decode DNS-tunneled data from a Suricata log file."
argument-hint: "[path to eve.json, default: eve.json in current directory] [optional: report_dir — case folder, default: report-<case>-hunt-dns-tunnel-<date> beside the log]"
allowed-tools: "Bash, Read, Write, Glob"
---

# Hunt DNS Tunneling in Suricata eve.json

Detect, confirm, decode, and report DNS tunneling from a Suricata `eve.json` log.

## Data handling — read before decoding

**Nothing derived from this log leaves the machine unless the user explicitly asks for
that specific act, in that specific message.** A request to hunt, decode, or "write up
the findings" is not approval to publish. Ask first, name the destination and what would
be sent, and wait for a yes.

**This routine reconstructs stolen data — the most sensitive artefact any hunt produces.**
A decoded tunnel payload is, by definition, what an attacker was exfiltrating: it may be
a customer document, a credential store, a private key, or an image of someone's screen.
Keep it on disk, hash it, describe what it is, and report the type and size. Never upload
it, never submit it to a sandbox or VirusTotal, and never embed it in a hosted or shared
report — including as an image.

Never do any of these on your own initiative: publishing an **Artifact** or any hosted
HTML report; submitting hashes, domains, IPs or decoded files to VirusTotal, urlscan.io,
a sandbox, or any threat-intel service; posting to Slack, Teams, email or a ticketing
system; `git push`, gists, pastebins; `curl`/`wget` POST, `scp`, webhooks, object-store
uploads — including through MCP tools.

Enrichment lookups disclose that you hold an indicator, and several services publish
submissions — which can tip off the actor and trigger destruction of evidence. Reasoning
about the tunnel domain offline needs no approval; sending it anywhere does.

**Deliver locally:** write the report to the case folder and the payload into its
`artifacts/` subfolder (see *Output layout* below), print the summary table and evidence
to the terminal, and tell the user the folder path. That is the finished deliverable.

**Always end with a terminal sum-up and raw evidence.** Naming the file path is not
delivery. After writing the report, print to the terminal (a) a short prose sum-up leading
with the verdict — compromised or not, which hosts, the headline numbers, what needs action
today, and what you assessed as benign — and (b) **at least two verbatim log excerpts**
copied from command output you actually ran, each with the `jq`/`grep` line above it so the
reader can re-run it. Never retype or reconstruct an excerpt; mark any truncation of a long
field as `...[truncated]`; keep `timestamp`/`flow_id`/`src_ip`/`dest_ip` in it. Evidence
distinct findings separately. See *Step 6* in the master skill. These excerpts are often the
most sensitive content in the log — terminal only, same as everything else here.

Two archetypes are covered:

| Archetype | Channel | Payload encoding | Tool example |
|---|---|---|---|
| **File exfil** | TXT rdata only | `[8-hex seq][base64 chunk]` per response | Custom scripts |
| **C2 tunnel** | MX + TXT + CNAME QNAME labels | hex-encoded binary in subdomain labels | dnscat2 |

## Arguments

- `eve_path` — Path to `eve.json` (default: `eve.json` in working directory)
- `report_dir` — Case report folder (default: `report-<case>-hunt-dns-tunnel-<YYYYMMDD-HHMM>` beside `eve.json`).
  The report goes in its root; the decoded payload and every other file go in `artifacts/`.
  See *Output layout* below.

---

## Output layout — the case report folder

**Every file this routine produces goes in one case folder. Nothing is written anywhere
else, and nothing is written next to the log loose.**

```bash
eve_dir=$(cd "$(dirname "$eve")" && pwd)
case_name=$(basename "$eve" | sed 's/[-_.]\?eve.*$//; s/\.json$//')
[ -n "$case_name" ] || case_name=case
report_dir="${report_dir:-$eve_dir/report-${case_name}-hunt-dns-tunnel-$(date +%Y%m%d-%H%M)}"
mkdir -p "$report_dir/artifacts"
plugin_dir="<the hunt plugin root you loaded this SKILL.md from>"   # holds tools/mdpretty.py
```

| Path | Contents |
|---|---|
| `$report_dir/hunt-dns-tunnel-report.md` | The full written report |
| `$report_dir/README.md` | Handling warning for whoever opens this folder later — **required**, see below |
| `$report_dir/artifacts/` | **Everything else**: `tunneled_payload.txt` (decoded/extracted payload, `.txt` so it cannot be executed), `reassembled_stream.b64`, `chunk_map.csv`, `tunnel_events.csv`, `query_rate_per_minute.csv`, `iocs.csv`, `sha256sums.txt` |

- **Naming:** `report-<case>-hunt-dns-tunnel-<YYYYMMDD-HHMM>`. The minute-resolution timestamp
  means re-running never overwrites a previous hunt, and no previous case folder is ever
  deleted to make room.
- **Location:** beside the EVE log — never in a skills or plugin repository, and never in
  a directory you did not create for this case.
- **If the master `hunt` skill invoked this routine** it passes `report_dir` in; use it
  rather than creating a second folder. Only create one when running standalone.
- **Integrity:** finish with `cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt`.
- **Scratch is not an artifact.** Intermediate passes go in `$(mktemp -d)` and are deleted
  — see *Clean up and housekeeping* at the end of this skill.

---


## Step 1 — Locate and size the file

```bash
wc -l eve.json
grep '"event_type":"dns"' eve.json | wc -l
```

### Detect the DNS schema version — do this before anything else

```bash
jq -r 'select(.event_type=="dns") | "v\(.dns.version // 1) \(.dns.type)"' eve.json | sort | uniq -c
```

Suricata has shipped three incompatible DNS EVE layouts. **v2 is the default through
Suricata 7.x; v3 is the default from Suricata 8.0.** `dns.version` is absent in v1, so
`// 1` is the correct default rather than a guess.

| | **v1** (no `version` key) | **v2** (`"version":2`) | **v3** (`"version":3`) |
|---|---|---|---|
| `dns.type` values | `query` / `answer` | `query` / `answer` | `request` / `response` |
| Query name | `dns.rrname` *(flat)* | `dns.rrname` *(flat)* | `dns.queries[].rrname` |
| Query type | `dns.rrtype` *(flat)* | `dns.rrtype` *(flat)* | `dns.queries[].rrtype` |
| Answer records | **one event per RR**, `dns.rdata` / `dns.rrtype` / `dns.ttl` flat | `dns.answers[]` array | `dns.answers[]` array |
| `dns.grouped` | absent | present | present |

Common to all versions: `dns.rcode` (`NOERROR`, `NXDOMAIN`, …), and `app_proto` is
**not emitted** on `dns` event_type records — it is implied by the event type itself;
use `"dns"` as the value when reporting.

**What this means for this skill:**

- **`dns.answers[]` is identical in v2 and v3.** All the answer-side work below —
  TXT rdata sampling, `[8-hex][base64]` reassembly, dnscat2 rdata parsing — is
  already portable across v2 and v3 unchanged. Only **v1** needs the fallback,
  because it emits one event per answer RR with the fields flat on `dns`.
- **The query side is what breaks.** Archetype 2 reads the payload out of the
  *QNAME*, so on a v1/v2 log every `dns.get('queries', [])` loop below silently
  iterates an empty list and the hunt reports a clean result on a live tunnel.
- **`.dns.query.rrname` — singular `query` — is not valid in any version.** If you
  see it anywhere, it is a bug that matches nothing.

### Compatibility helpers — prepend to every Python snippet in this skill

```python
def dns_version(dns):
    """1, 2 or 3. v1 has no 'version' key."""
    return dns.get('version', 1)

def dns_queries(dns):
    """Yield (rrname, rrtype) for v1, v2 and v3."""
    qs = dns.get('queries')
    if qs:                                    # v3
        for q in qs:
            yield q.get('rrname', ''), q.get('rrtype', '')
    elif dns.get('rrname'):                   # v1 / v2
        yield dns.get('rrname', ''), dns.get('rrtype', '')

def dns_answers(dns):
    """Yield answer dicts (rrname/rrtype/rdata/ttl) for v1, v2 and v3."""
    ans = dns.get('answers')
    if ans:                                   # v2 / v3
        yield from ans
    elif dns.get('rdata') is not None:        # v1 — one answer RR per event
        yield {'rrname': dns.get('rrname', ''), 'rrtype': dns.get('rrtype', ''),
               'rdata': dns.get('rdata', ''), 'ttl': dns.get('ttl')}

def is_request(dns):
    return dns.get('type') in ('request', 'query')

def is_response(dns):
    return dns.get('type') in ('response', 'answer')
```

The snippets in Steps 2–6 use these helpers throughout. Record the detected version and
state it in the report header.

---

## Step 2 — First-pass statistical analysis

Single Python pass collecting all indicators at once:

```python
import json, collections, math

def entropy(s):
    freq = collections.Counter(s.lower())
    l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())

versions = collections.Counter()
qtypes = collections.Counter()
domain_freq = collections.Counter()
long_domains = []
high_entropy = []
nxd_sources = collections.Counter()
unusual = []
big_rdata = collections.Counter()
first_ts = last_ts = None

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns':
            continue
        ts = e.get('timestamp', '')
        if not first_ts or ts < first_ts: first_ts = ts
        if not last_ts or ts > last_ts: last_ts = ts
        dns = e['dns']
        src = e.get('src_ip', '')
        versions[dns_version(dns)] += 1

        # Query side — only count queries on request events, so v1/v2 answer
        # events (which also carry a flat dns.rrname) are not double-counted.
        if is_request(dns):
            for name, rtype in dns_queries(dns):
                qtypes[rtype] += 1
                domain_freq[name] += 1
                labels = name.split('.')
                max_label = max(len(lb) for lb in labels) if labels else 0
                if len(name) > 50 or max_label > 30:
                    long_domains.append((name, rtype, src, len(name), max_label))
                subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else labels[0]
                if subdomain and len(subdomain) > 6 and entropy(subdomain) > 3.5:
                    high_entropy.append((entropy(subdomain), name, rtype, src))
                if rtype in ('TXT', 'MX', 'CNAME', 'NULL', 'ANY', 'HINFO', 'SRV', 'DNSKEY', 'DS', 'NAPTR'):
                    unusual.append((rtype, name, src))

        if is_response(dns):
            if dns.get('rcode') == 'NXDOMAIN':
                nxd_sources[e.get('dest_ip', '')] += 1
            # Answer side — catches tunnels whose payload is in the rdata, not
            # the QNAME. These are invisible to every query-name heuristic above.
            for ans in dns_answers(dns):
                rdata = ans.get('rdata') or ''
                if ans.get('rrtype') == 'TXT' and len(rdata) > 100:
                    big_rdata[(ans.get('rrname', ''), len(rdata))] += 1

    except:
        pass

print('DNS schema versions seen:', dict(versions))
print('Oversized TXT rdata (rrname, len) -> count:', big_rdata.most_common(10))
```

`versions` should hold a single key. If it holds more than one, the log is a
concatenation of captures from different Suricata versions — split it before hunting,
or every per-version count below will be wrong.

**Archetype 1 — file exfil red flags:**
- TXT > 20% of all queries is suspicious; > 50% is highly indicative
- Single domain dominates TXT volume by a large margin
- Consistent flat query rate (e.g. 78/min across 60 minutes) — automated tool

**Archetype 2 — C2 tunnel (dnscat2) red flags:**
- MX + TXT + CNAME together account for > 40% of DNS traffic
- Long domains: many FQDNs > 50 chars, individual labels > 30 chars
- All subdomains of an apex domain are pure lowercase hex strings
- Apex domain uses IDN/Punycode encoding (`xn--…`) — obfuscation
- Client queries an external resolver directly (e.g. `8.8.8.8`) — bypasses local DNS monitoring

---

## Step 3 — Identify tunnel archetype and deep-dive

### Archetype 1 — TXT base64 file exfil

Collect TXT rdata samples and check for `[8-hex][base64]` structure:

```python
for line in open('eve.json'):
    e = json.loads(line)
    dns = e.get('dns', {})
    if is_response(dns):
        for ans in dns_answers(dns):
            if ans.get('rrtype') == 'TXT' and 'suspectdomain.com' in ans.get('rrname', ''):
                print(ans.get('rdata', '')[:120])
```

Signatures in TXT rdata:
- `00000000<base64>`, `00000001<base64>`, … — chunked sequential file transfer
- Pure base64 without prefix — raw encoded data
- Hex-encoded binary
- Plaintext commands/responses — interactive shell (dnscat2 unencrypted)

Also scan all TXT rdata (any domain) for high-value content indicators:

```python
import json, re

UA_PATTERN = re.compile(r'\b(curl|wget|python|powershell)\b', re.IGNORECASE)
FILE_PATTERN = re.compile(r'\b\w[\w\-. ]*\.(exe|bat|ps1|sh|ppt|pptx|doc|docx|xls|xlsx)\b', re.IGNORECASE)

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns': continue
        dns = e['dns']
        if is_response(dns):
            for ans in dns_answers(dns):
                if ans.get('rrtype') != 'TXT': continue
                rdata = ans.get('rdata', '')
                flags = []
                if len(rdata) > 100:
                    flags.append(f'LONG({len(rdata)})')
                if UA_PATTERN.search(rdata):
                    flags.append('USER-AGENT:' + UA_PATTERN.search(rdata).group())
                if FILE_PATTERN.search(rdata):
                    flags.append('FILENAME:' + FILE_PATTERN.search(rdata).group())
                if flags:
                    print(f'[{", ".join(flags)}] {ans.get("rrname","")}')
                    print(f'  rdata: {rdata}')
    except:
        pass
```

### Archetype 2 — dnscat2 QNAME hex C2

Collect all queries to the apex domain:

```python
import json, collections

APEX = 'suspect.click'   # replace with identified apex
subdomains = collections.Counter()
src_ips = set()
resolver_ips = set()
rdata_samples = []

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns': continue
        dns = e['dns']
        if is_request(dns):
            for name, rtype in dns_queries(dns):
                if APEX in name:
                    subdomains[name] += 1
                    src_ips.add(e.get('src_ip', ''))
                    resolver_ips.add(e.get('dest_ip', ''))
        if is_response(dns):
            for ans in dns_answers(dns):
                if APEX in ans.get('rrname', '') and ans.get('rdata'):
                    rdata_samples.append(ans.get('rdata', ''))
    except:
        pass
```

QNAME subdomain structure (dnscat2 protocol):
```
[pkt-id 2B][msg-type 1B][session-id 2B][encrypted payload ...].apex.tld
```
- `msg-type`: `00`=SYN, `01`=MSG, `02`=FIN, `03`=PING
- Labels split at 63-char DNS limit; flatten by removing dots before parsing
- MX rdata and CNAME targets carry server→client data in the same hex format
- Responses end with a fixed `ffff…` seq/ack trailer

---

## Step 4 — Decode payload

### Archetype 1 — reconstruct base64 file

```python
import json, base64

chunks = {}
conflicts = 0
for line in open('eve.json'):
    e = json.loads(line)
    dns = e.get('dns', {})
    if is_response(dns):
        for ans in dns_answers(dns):
            if ans.get('rrtype') == 'TXT' and 'suspectdomain.com' in ans.get('rrname', ''):
                raw = ans.get('rdata', '')
                if len(raw) >= 8:
                    try:
                        seq = int(raw[:8], 16)
                    except ValueError:
                        continue
                    body = raw[8:]
                    if seq in chunks and chunks[seq] != body:
                        conflicts += 1        # retransmit with different payload
                    chunks[seq] = body

sorted_keys = sorted(chunks.keys())
full_b64 = ''.join(chunks[k] for k in sorted_keys)
decoded = base64.b64decode(full_b64 + '==')
print(f'Chunks: {len(chunks)}, seq range: {min(sorted_keys)}-{max(sorted_keys)}, conflicts: {conflicts}')
print(f'Decoded: {len(decoded)} bytes, magic: {decoded[:4].hex()}, tail: {decoded[-4:].hex()}')
```

Deduplicating into a dict keyed by `seq` matters on **v1** logs in particular: v1 emits
one event per answer RR, so the same chunk can arrive as several events. `conflicts`
should be 0 — a non-zero count means two different payloads claimed the same sequence
number, so the reassembly is not trustworthy.

**Do not require the sequence numbers to be dense.** Real tools skip values. Verify the
result by its file structure — magic bytes *and* a valid trailer (e.g. `ffd9` for JPEG),
plus a clean parse by a real decoder — not by whether `seq` increments neatly.

Common magic bytes:

| Hex | File type |
|---|---|
| `ffd8ffe0` / `ffd8ffe1` | JPEG image |
| `89504e47` | PNG image |
| `25504446` | PDF |
| `504b0304` | ZIP / Office document |
| `7f454c46` | ELF binary (Linux) |
| `4d5a9000` | PE/EXE (Windows) |
| `1f8b0800` | gzip archive |

### Archetype 2 — extract dnscat2 session bytes

Parse all tunnel packets by session, separating client→server (Q) and server→client (R) bytes:

```python
import json, collections, struct

APEX = 'suspect.click'
TYPE_NAMES = {0: 'SYN', 1: 'MSG', 2: 'FIN', 3: 'PING'}
sessions = collections.defaultdict(lambda: {'Q': [], 'R': []})

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns': continue
        dns = e['dns']
        ts = e.get('timestamp', '')

        if is_request(dns):
            for name, rtype in dns_queries(dns):
                if APEX not in name: continue
                hex_data = name.replace('.' + APEX, '').replace('.', '')
                if len(hex_data) >= 10:
                    raw = bytes.fromhex(hex_data)
                    sess = raw[3:5].hex()
                    sessions[sess]['Q'].append({'type': raw[2], 'data': raw[5:], 'ts': ts})

        if is_response(dns):
            for ans in dns_answers(dns):
                if APEX not in ans.get('rrname', ''): continue
                rdata = ans.get('rdata', '').replace('.' + APEX, '').replace('.', '')
                if len(rdata) >= 10:
                    raw = bytes.fromhex(rdata)
                    sess = raw[3:5].hex()
                    sessions[sess]['R'].append({'type': raw[2], 'data': raw[5:], 'ts': ts})
    except:
        pass

# Check SYN packets for session name
for sid, pkts in sessions.items():
    for p in pkts['Q'] + pkts['R']:
        if p['type'] == 0 and len(p['data']) >= 4:
            isn = struct.unpack('>H', p['data'][0:2])[0]
            name = p['data'][4:].split(b'\x00')[0].decode('utf-8', errors='replace')
            print(f'Session {sid}: ISN={isn:#06x} name={repr(name)}')
```

dnscat2 sessions are encrypted by default — raw bytes will be binary. Extract and save them; do not attempt to decrypt without the session key.

---

## Step 5 — Assess query timing and rate

```python
minute_counts = collections.Counter()
seen_tx = set()
for line in open('eve.json'):
    e = json.loads(line)
    if e.get('event_type') != 'dns': continue
    dns = e['dns']
    if is_request(dns):
        for name, rtype in dns_queries(dns):
            if 'suspectdomain' in name:
                # Suricata may log the same query under several tx_id values;
                # key on (flow_id, dns.id) so the rate reflects real queries.
                k = (e.get('flow_id'), dns.get('id'))
                if k in seen_tx: continue
                seen_tx.add(k)
                minute_counts[e.get('timestamp', '')[:16]] += 1

vals = [minute_counts[k] for k in sorted(minute_counts)]
for ts, cnt in sorted(minute_counts.items()):
    print(f'{ts}: {cnt}')
if vals:
    print(f'minutes={len(vals)} min={min(vals)} max={max(vals)} mean={sum(vals)/len(vals):.1f}')
```

**Deduplicate before reporting a rate.** Suricata commonly emits the same query more
than once (different `tx_id`), and **v1 emits one event per answer RR**, so a naive
count inflates the rate — by exactly 2× on some v3 logs. Always sanity-check the raw
event count against the distinct-query count before quoting queries/min.

A flat, consistent rate across many minutes = automated tool. A short burst at very high rate (e.g. 300+/min over 90 seconds) = dnscat2 retransmit behavior.

---

## Step 6 — Look up flow sizes from event_type:flow

For each representative flow_id in the example events, find the matching `event_type:flow` record to get bytes transferred:

```python
import json

target_flows = {339169965393785, 287532207143557}   # replace with actual IDs

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'flow': continue
        if e.get('flow_id') in target_flows:
            f = e.get('flow', {})
            print(f"flow_id={e['flow_id']} "
                  f"toserver={f.get('bytes_toserver')} "
                  f"toclient={f.get('bytes_toclient')} "
                  f"app_proto={e.get('app_proto')}")
    except:
        pass
```

Report flow size as `N B (→toserver ←toclient)` in the events table.

---

## Step 7 — Save decoded payload

Write decoded/extracted data to disk with `.txt` extension so it is not accidentally executed:

All of these go in `$report_dir/artifacts/`, never in the folder root and never loose
beside the log.

```python
import os, hashlib
ART = os.path.join(report_dir, 'artifacts')

# Archetype 1 — binary payload
with open(os.path.join(ART, 'tunneled_payload.txt'), 'wb') as f:
    f.write(decoded)

# Archetype 2 — session hex dump
with open(os.path.join(ART, 'tunneled_payload.txt'), 'w') as f:
    f.write('DNSCAT2 TUNNEL SESSIONS — RAW EXTRACTED DATA\n')
    for sid, pkts in sorted(sessions.items()):
        q_data = b''.join(p['data'] for p in sorted(pkts['Q'], key=lambda x: x['ts']) if p['type'] == 1)
        r_data = b''.join(p['data'] for p in sorted(pkts['R'], key=lambda x: x['ts']) if p['type'] == 1)
        f.write(f'\n--- Session {sid} ---\n')
        f.write(f'  C->S bytes: {len(q_data)}\n')
        f.write(f'  S->C bytes: {len(r_data)}\n')
        for i in range(0, len(q_data), 32):
            f.write(f'  C->S {i:04x}: {q_data[i:i+32].hex()}\n')
        for i in range(0, len(r_data), 32):
            f.write(f'  S->C {i:04x}: {r_data[i:i+32].hex()}\n')
```

Then hash it and identify it — both belong in the report:

```python
print(hashlib.sha256(decoded).hexdigest(), len(decoded))
```
```bash
file "$report_dir/artifacts/tunneled_payload.txt"
```

**Never execute, open, run, `chmod +x`, render or upload the decoded payload.** The `.txt`
extension is deliberate. Verify it structurally instead — magic bytes *and* a valid
trailer, plus a clean parse by a real decoder — and report the type, size and hash.

---

## Step 8 — Print report

Print the full report to the terminal. Always include the events table.

**CRITICAL — dns.rrname and dns.rdata must always be printed in full, never truncated.**
- `dns.rrname` may be up to 253 characters (multi-label hex domains in dnscat2 or iodine uploads) — print every character.
- `dns.rdata` for TXT may be up to 256 characters (iodine A–P base16 or base64 chunks) — print every character.
- Never use `[:N]`, `...`, or ellipsis to shorten these fields in the table or anywhere in the report.
- If a cell value is long, let the table row wrap — do not abbreviate the data.

```
╔══════════════════════════════════════════════════════════════════════╗
║         DNS TUNNEL HUNT REPORT — Suricata eve.json                   ║
╠══════════════════════════════════════════════════════════════════════╣
║  File    : /path/to/eve.json                                         ║
║  Lines   : N total  |  N DNS events  |  DNS schema vN                ║
║  Window  : YYYY-MM-DDTHH:MM  →  HH:MM  (~N seconds/minutes)         ║
╠══════════════════════════════════════════════════════════════════════╣
║  VERDICT :  CONFIRMED — [ARCHETYPE] DETECTED                        ║
╚══════════════════════════════════════════════════════════════════════╝

── DNS RESOLVERS ──────────────────────────────────────────────────────
  x.x.x.x     description (local resolver / Google DNS / C2 auth NS)

── VICTIM IPs ─────────────────────────────────────────────────────────
  x.x.x.x     description

── TUNNEL DOMAIN / SESSIONS ───────────────────────────────────────────
  [domain / session summary]

── EXAMPLE TUNNEL EVENTS ──────────────────────────────────────────────

| # | event_type | app_proto | src_ip | dest_ip | flow_id | flow size | rrtype | dns.rrname (query) — FULL, never truncated | dns.rdata (answer) — FULL, never truncated | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | dns | dns * | ... | ... | ... | N B (→N ←N) | ... | full rrname value | full rdata value | ... |
...

  rrname structure: [pkt-id 2B][msg-type 1B][session-id 2B][payload ...].apex.tld
  rdata  structure: [pkt-id 2B][msg-type 1B][session-id 2B][payload ...][seq/ack in brackets]

  † / ‡ footnotes as needed
  * app_proto not emitted by Suricata on dns event_type; implied by event_type itself

── INDICATOR CHECKLIST ────────────────────────────────────────────────
  [FAIL/PASS]  indicator  →  observed value

── OUTPUT ─────────────────────────────────────────────────────────────
  <report_dir>/
    hunt-dns-tunnel-report.md
    artifacts/  tunneled_payload.txt, reassembled_stream.b64, chunk_map.csv,
                tunnel_events.csv, query_rate_per_minute.csv, iocs.csv,
                sha256sums.txt
```


### Always print a summary table to the terminal as well

The report file is the record; the terminal table is what the reader actually sees.
**Print both, every run** — writing the file is not delivery.

Render a compact `| Item | Value |` table with `printf` so the columns align, directly
under the boxed verdict banner. Keep it to one screen, and carry at minimum: verdict,
affected internal host(s), attacker infrastructure, the headline counts and percentages,
the activity window and rate, any reconstructed artefact (size, SHA-256, identified type,
validation result), whether any Suricata signature fired, and the case folder path with
the report filename and artifact count.

Every value in the table must already appear in the report file — the table condenses,
it never adds a new claim.

```bash
printf '| %-24s | %-49s |\n' "Item" "Value"
printf '|%s|%s|\n' "$(printf '%.0s-' {1..26})" "$(printf '%.0s-' {1..51})"
printf '| %-24s | %-49s |\n' \
  "Verdict"           "<CONFIRMED|SUSPECTED|CLEAN> — <threat class>" \
  "Affected host(s)"  "<internal IPs>" \
  "Attacker infra"    "<external IPs / domains>" \
  "Headline volume"   "<counts, percentages, bytes>" \
  "Window / rate"     "<first -> last, events per minute>" \
  "Suricata alerts"   "<n on this activity>" \
  "Report"            "hunt-dns-tunnel-report.md" \
  "Artifacts"         "<n> files in artifacts/"
```

---

## Checklist — tunneling indicators

| Indicator | Archetype | How to detect |
|---|---|---|
| TXT > 20% of DNS volume | File exfil | Query type distribution |
| Single domain dominates TXT | File exfil | Top queried domains |
| Sequential hex+base64 in TXT rdata | File exfil | `00000000<b64>` pattern in rdata |
| Base64 decodes to known file magic | File exfil | Check first 4 bytes after decode |
| Consistent flat query rate | File exfil | Per-minute count over many minutes |
| MX + TXT + CNAME combined > 40% | C2 tunnel | Query type distribution |
| Long FQDN labels (> 30 chars) | C2 tunnel | Max label length per query |
| All subdomains are pure hex strings | C2 tunnel | Subdomain character set check |
| dnscat2 SYN handshake in QNAME | C2 tunnel | `type=00` byte in hex subdomain |
| Multiple concurrent sessions | C2 tunnel | Distinct session-id bytes (offset 3–4) |
| IDN / Punycode apex domain | C2 tunnel | `xn--` prefix in apex domain |
| Client bypasses local resolver | C2 tunnel | Queries direct to 8.8.8.8 or similar |
| Rotating A record IPs | Both | Many distinct A records per domain |
| No Suricata signatures fired | Both | Empty fast.log for tunnel domain |
| TXT rdata longer than 100 chars | Both | `len(rdata) > 100` in TXT answers |
| User-agent strings in TXT rdata | Both | Grep rdata for `curl`, `wget`, `python`, `powershell` (case-insensitive) |
| Executable or document filenames in TXT rdata | Both | Grep rdata for `.exe`, `.bat`, `.ps1`, `.sh`, `.ppt`, `.doc`, `.xls` (case-insensitive) |


### Pretty-print the report to the terminal

Raw Markdown in a terminal is not a delivery. Render the report with the bundled printer
(no Markdown viewer required):

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-dns-tunnel-report.md"
```

Colour is automatic — ANSI on a TTY, plain text when redirected, so `> out.txt` never
captures escape codes. Width follows `$COLUMNS` (cap 118); `--width N` and `--no-color`
override. Tables too wide for a grid become one labelled block per row, which is what
keeps `dns.rrname` and `dns.rdata` untruncated as this routine requires.



### Write `README.md` — the handling warning — into every case folder

**Required, every hunt, before you finish.** A case folder outlives the session and gets
opened by someone who was not here: it lists live attacker infrastructure and may contain
functional malware or genuine stolen data. It must warn them at the door.

Write `$report_dir/README.md` — folder root, beside the report, never in `artifacts/`:

```markdown
# READ ME FIRST — handle the contents of this folder with care

This folder holds the output of an automated threat hunt over a Suricata EVE JSON log. The
domains, IP addresses, URLs and hashes recorded here are what the hunt flagged as worth a
look: some may be genuine attacker activity, others may be ordinary traffic that merely
resembled it. Which is which is not settled until an analyst has verified it — so until
then, treat anything in this folder as potentially dangerous rather than assuming either way.

> ## ⚠ CAUTION — TREAT AS POTENTIALLY ACTIVE UNTIL ASSESSED
>
> **Any indicator recorded here may be live, and any extracted or reconstructed payload in
> `artifacts/` may be active malware or genuine stolen data.** You cannot tell which from
> the report alone, which is exactly why the caution applies to all of it. Do not open, run,
> double-click or preview any artifact file, and do not visit, resolve or connect to any
> domain, URL or address listed in this report from a normal workstation. Payload files are
> deliberately saved with a `.txt` extension so they cannot be launched by accident — that
> is a safety net, not permission to open them.
>
> **Where the report confirms malware or an active compromise, treat the above as hard
> rules:** work only in an isolated analysis environment, never on a production or personal
> machine, and share this folder strictly on a need-to-know basis.

**Start here:** `hunt-dns-tunnel-report.md` — the full findings, including whatever was assessed as benign.
Supporting evidence is in `artifacts/`, with `artifacts/sha256sums.txt` fixing its integrity.
```

Keep the wording above and keep it generic. Adjust only the "Start here" line to name this
hunt's report file, and add at most one sentence naming the specific hazard when the hunt
reconstructed something unusually sensitive (a credential store, a private key, a customer
document). Do not soften the CAUTION block, and do not drop it because a particular hunt
found nothing — a clean hunt's folder still lists the indicators that were checked.

**The README states a handling posture, never a verdict.** A hunt surfaces candidates, and
a good proportion of them turn out to be benign — a CDN with high-entropy hostnames, an
appliance with a self-signed certificate, a backup job that looks like exfiltration. Do not
write that this folder contains attacker activity, hostile infrastructure or a confirmed
compromise: that claim belongs in the report, where it is argued from evidence and can say
"assessed benign" just as easily. The README's job is narrower and does not depend on the
outcome — *you cannot tell what is dangerous before it is verified, so handle all of it
carefully until someone has.* Where the report does confirm malware or an active
compromise, the same caution stops being advice and becomes a hard rule; the template says
so, and that sentence stays in whether or not this particular hunt found anything.

**Keep this file free of tool, vendor and workflow instructions.** It is a hazard label for
whoever opens the folder, not a policy document: no named third-party services, no analysis
procedure, no do-not-upload lists. What may and may not be done with the data is a decision
for the analyst and their organisation, and it lives in the routine's *Data handling*
section — not in a README that travels with the evidence.


### Always pretty-print the finished report — the last act of the routine

**Render the report at the end of every run, unprompted.** A file path is not a delivery.

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-dns-tunnel-report.md"
```

**Shell output is not reliably shown to the user** — it goes to the model. After rendering,
**reproduce the report in your own reply message as Markdown**, which is what the user
actually reads. If the user has to ask for the report a second time, it was not delivered.


---

## Clean up and housekeeping

**Scratch is deleted. Evidence is kept.** Getting that backwards either destroys the
deliverable or leaves the victim's data in `/tmp`. Run this at the end of every hunt, and
after an aborted one.

| Keep — the deliverable | Delete — scratch |
|---|---|
| `$report_dir/hunt-dns-tunnel-report.md` and `README.md` | Ad-hoc Python/`jq` scripts written to run one pass |
| `$report_dir/artifacts/*` and its `sha256sums.txt` | Sorted/uniq'd intermediates, split chunks, partial greps |
| The original `eve.json` — **never touched, moved or modified** | Everything under `$(mktemp -d)`, and the temp dir itself |
| Anything the user created or named | Convenience copies of the EVE log |

### Temp file rules

- **`mktemp` only** — never a predictable name. A fixed path in a world-writable
  directory is a symlink-attack target and collides between concurrent hunts.
- **One temp dir per run, `trap`-removed**, so an aborted hunt still cleans up:

  ```bash
  tmp=$(mktemp -d) || exit 1
  chmod 700 "$tmp"
  trap 'rm -rf "$tmp"' EXIT INT TERM
  ```

- **Restrictive permissions** — scratch holds decoded data and internal addressing on a
  possibly shared host. `umask 077` before writing anything sensitive.
- **Clean up after the report and artifacts are written and verified**, never while a
  later step still needs the files.

### Deletion safety

- **Delete only paths you created in this run.** `rm -rf "$tmp"` is safe because `$tmp`
  came from `mktemp`; `rm -rf /tmp/*` never is.
- **Never `rm -rf` an unquoted or possibly-empty variable** — unset `$tmp` targets `/`.
  Guard it: `[ -n "$tmp" ] && [ -d "$tmp" ] && rm -rf "$tmp"`.
- **Never delete, truncate, rewrite, re-compress or move the source `eve.json`.** This
  routine is read-only over it by design; it is the evidence, and it may be under legal
  hold.
- **Never delete a previous case folder.** The timestamp in the name exists so runs
  accumulate. Pruning is the user's call.
- **Look before you overwrite.** If a target path exists, pick a new name rather than
  clobbering what may be another analyst's evidence.
- **Never execute or open a reconstructed payload.** Write it with a `.txt` extension,
  never `chmod +x`, never hand it to a renderer or interpreter. Hash it, identify it with
  `file(1)`, describe it.

### Resource housekeeping on large logs

- **Stream, never slurp.** `eve.json` is routinely tens of GB — line-by-line `jq -c`,
  `grep`, or streaming Python only. Never `jq -s`, never `json.load(open(...))`.
- **Prefilter with `grep` before `jq`** — `jq` parses every line handed to it.
- **Check free space** before writing large artifacts: `df -h "$report_dir"`.
- **Bound anything unbounded** — cap in-memory counters and sample lists so an enormous
  or hostile log cannot exhaust RAM.

### Final checklist — print the outcome, don't just do it

```bash
cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt
[ -n "$tmp" ] && [ -d "$tmp" ] && rm -rf "$tmp"
ls -la "$report_dir" "$report_dir/artifacts"
```

- [ ] Report written to `$report_dir/hunt-dns-tunnel-report.md`
- [ ] `$report_dir/README.md` written, with the CAUTION block intact
- [ ] Report pretty-printed **and reproduced in the reply message** — not just a path
- [ ] Every supporting file in `$report_dir/artifacts/`, nothing loose elsewhere
- [ ] `artifacts/sha256sums.txt` written, covering every artifact but itself, and `sha256sum -c` passes
- [ ] Source `eve.json` unmodified — same size, same mtime
- [ ] Scratch dir removed; nothing sensitive left in `/tmp`
- [ ] No reconstructed payload is executable, and none was executed or opened
- [ ] Nothing left the machine (see *Data handling*)
- [ ] Summary table and raw evidence excerpts printed to the terminal
- [ ] Case folder path stated to the user
