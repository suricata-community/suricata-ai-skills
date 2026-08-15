---
name: hunt-generic
description: Generic high-level threat hunt over a Suricata EVE JSON log. Runs 10 systematic hunts covering high-severity alerts, HTTP-to-IP with suspicious user agents, high-risk TLDs, large outbound transfers, DNS length/entropy anomalies, rare protocols and ports, beaconing, TLS/certificate anomalies, internal reconnaissance, and HTTP method/path abuse, then compiles the findings into a structured report.
argument-hint: "[path to eve.json, default: eve.json in current directory] [optional: report_dir — case folder, default: report-<case>-hunt-generic-<date> beside the log]"
allowed-tools: "Bash, Read, Write, Glob, Grep"
---

# Hunt: High-Priority Threat Hunting

Execute these hunting queries systematically and report findings.

## Data handling — read before reporting

**Nothing derived from this log leaves the machine unless the user explicitly asks for
that specific act, in that specific message.** A request to hunt, analyse, or "write up
the findings" is not approval to publish. Ask first, name the destination and what would
be sent, and wait for a yes.

Never do any of these on your own initiative: publishing an **Artifact** or any hosted
HTML report; submitting hashes, domains, IPs or files to VirusTotal, urlscan.io, a
sandbox, or any threat-intel service; posting to Slack, Teams, email or a ticketing
system; `git push`, gists, pastebins; `curl`/`wget` POST, `scp`, webhooks, object-store
uploads — including through MCP tools.

The log holds internal addressing, hostnames, live attacker infrastructure and sometimes
the victim's own stolen data. Enrichment lookups disclose that you hold an indicator, and
several services publish submissions — which can tip off the actor. Reasoning about an
indicator offline needs no approval; sending it anywhere does.

**Deliver locally:** print the report to the terminal, or write it beside the log and
tell the user the path. That is the finished deliverable. Suggest a hosted version in one
sentence if it would genuinely help, then stop.

## Input

This skill reads a **Suricata EVE JSON log** (JSONL — one JSON object per line). Every
query below assumes the shell variable `$eve` holds its path:

```bash
eve="eve.json"   # or the path the user supplied
wc -l "$eve"
```

If the user has no EVE JSON — only a capture file — stop and ask them to produce one;
this skill does not read capture files.

**IMPORTANT**: When executing multiple hunts, combine them into a single Bash command to avoid multiple confirmation prompts. Use semicolons to chain commands and echo separators for clarity.

## Output layout — the case report folder

**Every file this routine produces goes in one case folder. Nothing is written anywhere
else, and nothing is written next to the log loose.**

```bash
eve_dir=$(cd "$(dirname "$eve")" && pwd)
case_name=$(basename "$eve" | sed 's/[-_.]\?eve.*$//; s/\.json$//')
[ -n "$case_name" ] || case_name=case
report_dir="${report_dir:-$eve_dir/report-${case_name}-hunt-generic-$(date +%Y%m%d-%H%M)}"
mkdir -p "$report_dir/artifacts"
plugin_dir="<the hunt plugin root you loaded this SKILL.md from>"   # holds tools/mdpretty.py
```

| Path | Contents |
|---|---|
| `$report_dir/hunt-generic-report.md` | The full written report |
| `$report_dir/README.md` | Handling warning for whoever opens this folder later — **required**, see below |
| `$report_dir/artifacts/` | **Everything else**: one CSV per hunt that produced rows (`hunt01_alerts.csv` … `hunt10_http_methods.csv`), `iocs.csv`, `sha256sums.txt` |

- **Naming:** `report-<case>-hunt-generic-<YYYYMMDD-HHMM>`. The minute-resolution timestamp
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

### Detect the DNS schema version first — required before Hunts 3 and 5

Suricata emits three incompatible DNS layouts. The query name lives in a different place
in each, so a query written for one version returns **zero rows against the others — and
zero rows is indistinguishable from a clean result**. Run this before any DNS hunt:

```bash
echo "=== DNS schema version ==="
jq -r 'select(.event_type=="dns") | "v\(.dns.version // 1) \(.dns.type)"' "$eve" | sort | uniq -c
```

| | **v1** (no `version` key) | **v2** (`"version":2`) | **v3** (`"version":3`) |
|---|---|---|---|
| `dns.type` values | `query` / `answer` | `query` / `answer` | `request` / `response` |
| Query name | `dns.rrname` *(flat)* | `dns.rrname` *(flat)* | `dns.queries[].rrname` |
| Answer records | one event per RR, `dns.rdata` flat | `dns.answers[]` | `dns.answers[]` |

v2 is the default through Suricata 7.x; v3 is the default from Suricata 8.0.
**`.dns.query.rrname` — singular `query` — is not valid in any version.**

Hunts 3 and 5 below use these helpers. Define `$DNSC` once at the top of your hunt
command and reuse it; it makes every DNS query version-agnostic:

```bash
# The trailing `|| true` matters: `read -d ''` always exits 1 at EOF, which aborts the
# script under `set -e` or breaks an && chain — even though $DNSC is populated correctly.
read -r -d '' DNSC <<'JQ' || true
def is_dns_request: (.dns.type == "request" or .dns.type == "query");
def is_dns_response:(.dns.type == "response" or .dns.type == "answer");
def dns_queries:
  if (.dns.queries? // null) != null then .dns.queries[]
  elif (.dns.rrname? // null) != null then {rrname: .dns.rrname, rrtype: .dns.rrtype}
  else empty end;
def dns_answers:
  if (.dns.answers? // null) != null then .dns.answers[]
  elif (.dns.rdata? // null) != null then
       {rrname: .dns.rrname, rrtype: .dns.rrtype, rdata: .dns.rdata, ttl: .dns.ttl}
  else empty end;
JQ
```

Record the version you found and state it in the report's Network Baseline.

This skill provides structured threat hunting methodologies for detecting:
- Malware C2 (Command & Control) communications
- Data exfiltration attempts
- Suspicious user agents and connection patterns
- Domain generation algorithms (DGA)
- Malicious TLDs and hosting infrastructure
- Lateral movement and reconnaissance
- Protocol anomalies and evasion techniques

## Hunt 1: Alert Signatures (If Rules Loaded)

**Objective**: Enumerate every signature that fired, ranked by volume, and pick out the
specific ones worth investigating.

```bash
# Every signature that fired — grouped by rule msg, no severity filter.
grep '"event_type":"alert"' "$eve" \
  | jq -Rr 'fromjson?' \
  | jq -s 'group_by(.alert.signature)
           | map({ sid:       .[0].alert.signature_id,
                   signature: .[0].alert.signature,
                   category:  .[0].alert.category,
                   count:     length,
                   src_ips:   [.[].src_ip]  | unique,
                   dest_ips:  [.[].dest_ip] | unique,
                   flow_ids:  [.[].flow_id] | unique | .[0:10] })
           | sort_by(-.count)'
```

**Do not filter this by severity.** `alert.metadata.signature_severity` is a free-text
tag typed by the rule author and left unset by most rulesets, and the numeric
`alert.severity` comes from the rule's `priority:`/`classtype` — falling back to a
compiled-in default — with `classification.config` editable per site. Both describe how
a rule was written, not how dangerous the traffic is, so the same rule on the same
packet can rank differently in two environments. A `Critical|Major` filter drops
everything that never set the tag: on a real 46k-alert log that is **98% of the alerts**,
including the DCSync and lateral-movement rules that fired tens of thousands of times.
See *Do not triage on alert severity* in the master skill.

**Look for:**
- Alerts related to malware, exploits, C2 traffic — judged by what the `msg:` describes
- **Low-count, high-specificity signatures.** A rule that fired twice is often the
  finding; a rule that fired 20,000 times is usually tuning debt. Read both ends of the
  distribution, not just the top.
- Repeated hits concentrated on one internal host
- Signatures that corroborate a behavioural finding from another hunt — that pairing is
  worth far more than any severity label

**Report format:**
- Signature name and `sid`
- Number of occurrences
- Affected hosts (src/dst IPs)
- Flow IDs for investigation
- Whether it corroborates or contradicts the behavioural hunts

## Hunt 2: Suspicious HTTP User Agents to IP Addresses

**Objective**: Find direct HTTP connections to IP addresses (no domain) with suspicious user agents

```bash
# HTTP connections to IPs with user agent details
jq -r 'select(.event_type=="http" and .http.hostname and (.http.hostname | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))) | {ip: .http.hostname, agent: .http.http_user_agent, src: .src_ip, dst: .dest_ip, flow_id: .flow_id, url: .http.url}' "$eve" | jq -s 'group_by(.ip) | map({target_ip: .[0].ip, agents: [.[].agent] | unique, count: length, sources: [.[].src] | unique, sample_flow: .[0].flow_id})'
```

**Suspicious indicators:**
- Generic user agents: `curl`, `wget`, `python-requests`, `Go-http-client`
- Missing or minimal user agents
- Outdated browser versions
- Scripting language agents: `Python`, `PowerShell`, `ruby`

**Why this matters:**
- Malware often connects to IP addresses instead of domains
- Legitimate browsers rarely connect directly to IPs
- C2 infrastructure often uses IP-based callbacks

**Report format:**
- Target IP address
- User agent(s) used
- Source IPs making the connections
- Sample flow_id for detailed investigation

## Hunt 3: Suspicious TLDs (.xyz, .top, .cc, etc.)

**Objective**: Identify connections to high-risk top-level domains

```bash
# DNS queries to suspicious TLDs  (version-agnostic — needs $DNSC from the Input section)
jq -r "$DNSC"'
  select(.event_type=="dns" and is_dns_request)
  | dns_queries as $q
  | select($q.rrname | test("\\.(xyz|top|cc|tk|ml|ga|cf|gq|pw|loan|download|click|stream|science)$"))
  | {domain: $q.rrname, rrtype: $q.rrtype, src_ip: .src_ip, flow_id: .flow_id}' "$eve" \
  | jq -s 'group_by(.domain) | map({domain: .[0].domain, rrtypes: [.[].rrtype] | unique, sources: [.[].src_ip] | unique, count: length, sample_flow: .[0].flow_id})'

# Always also print the full TLD distribution — a clean hit-list means nothing if the
# actor used a .com. This is what tells you the TLD heuristic simply did not apply.
jq -r "$DNSC"'select(.event_type=="dns" and is_dns_request)|dns_queries|.rrname' "$eve" \
  | awk -F. '{print $NF}' | sort | uniq -c | sort -rn

# HTTP/HTTPS connections to suspicious TLDs
jq -r 'select(.event_type=="http" and .http.hostname and (.http.hostname | test("\\.(xyz|top|cc|tk|ml|ga|cf|gq|pw|loan|download|click|stream|science)$"))) | {domain: .http.hostname, agent: .http.http_user_agent, src_ip: .src_ip, flow_id: .flow_id}' "$eve" | jq -s 'group_by(.domain) | map({domain: .[0].domain, agents: [.[].agent] | unique, sources: [.[].src_ip] | unique, count: length, sample_flow: .[0].flow_id})'
```

**High-risk TLDs:**
- `.xyz`, `.top` - Commonly used for malware/phishing
- `.cc`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq` - Free domains, abuse-prone
- `.pw`, `.loan`, `.download`, `.click` - Associated with malicious campaigns

**Report format:**
- Domain name with suspicious TLD
- Source IPs querying/connecting
- User agents (for HTTP/HTTPS)
- Number of connections
- Sample flow_id

## Hunt 4: Data Exfiltration - Large Outbound Transfers

**Objective**: Detect potential data theft via large uploads

```bash
# Flows with large client-to-server transfers (>10MB)
jq 'select(.event_type=="flow" and .flow.bytes_toserver > 10000000) | {src_ip: .src_ip, dst_ip: .dest_ip, dst_port: .dest_port, bytes: .flow.bytes_toserver, duration: .flow.age, proto: .app_proto, flow_id: .flow_id}' "$eve" | jq -s 'sort_by(.bytes) | reverse'
```

**Look for:**
- Large uploads to external IPs
- Uploads on uncommon ports
- Encrypted protocols (TLS) to unknown destinations
- Multiple small uploads to the same destination (beaconing with data)

**Report format:**
- Source IP (internal host)
- Destination IP and port
- Bytes transferred
- Duration of transfer
- Protocol used
- Flow_id

## Hunt 5: DNS Tunneling and DGA Detection

**Objective**: Identify DNS-based data exfiltration or domain generation algorithms

```bash
# Long DNS queries (potential tunneling)  — needs $DNSC from the Input section
jq -r "$DNSC"'
  select(.event_type=="dns" and is_dns_request)
  | dns_queries as $q
  | select(($q.rrname | length) > 40)
  | {domain: $q.rrname, rrtype: $q.rrtype, length: ($q.rrname | length),
     max_label: ([$q.rrname | split(".")[] | length] | max),
     src_ip: .src_ip, flow_id: .flow_id}' "$eve" \
  | jq -s 'unique_by(.domain) | sort_by(.length) | reverse | .[0:20]'

# High entropy domains (potential DGA)
jq -r "$DNSC"'
  select(.event_type=="dns" and is_dns_request)
  | dns_queries as $q
  | {domain: $q.rrname, src_ip: .src_ip, flow_id: .flow_id}' "$eve" \
  | jq -s 'map(select(.domain | test("[bcdfghjklmnpqrstvwxyz]{8,}"))) | unique_by(.domain) | .[0:20]'

# Query-type distribution — a TXT/MX/CNAME-heavy log is a tunnel candidate regardless
# of how ordinary the names look.
jq -r "$DNSC"'select(.event_type=="dns" and is_dns_request)|dns_queries|.rrtype' "$eve" \
  | sort | uniq -c | sort -rn

# Oversized answer rdata — catches tunnels that hide payload in the ANSWER rather than
# the QNAME, which every length/entropy check above will miss by construction.
jq -r "$DNSC"'
  select(.event_type=="dns" and is_dns_response)
  | dns_answers as $a
  | select($a.rrtype=="TXT" and (($a.rdata // "") | length) > 100)
  | "\(($a.rdata|length))\t\($a.rrname)"' "$eve" \
  | sort | uniq -c | sort -rn | head -20
```

**If Hunt 5 returns nothing, do not conclude "no DNS tunnelling".** These heuristics
only fire on long or random *query names*. A tunnel using a short fixed QNAME with the
payload in TXT answers passes all of them — that is what the last two queries above are
for, and it is why `@hunt-dns-tunnel` exists as a dedicated routine.

**DGA indicators:**
- Long random-looking domain names
- High ratio of consonants to vowels
- Unusual character patterns
- Numeric sequences in domains
- Queries with no successful resolution

**Report format:**
- Suspicious domain name
- Length or entropy indicator
- Source IP making queries
- Sample flow_id

## Hunt 6: Rare/Uncommon Protocols

**Objective**: Identify unusual protocols that may indicate lateral movement or tunneling

```bash
# Protocol distribution with rare ones highlighted
jq -r 'select(.event_type=="flow") | .app_proto // "unknown"' "$eve" | sort | uniq -c | sort -n

# Connections using uncommon ports
jq 'select(.event_type=="flow" and .dest_port and (.dest_port > 1024 and .dest_port < 49152) and .app_proto != "tls" and .app_proto != "http") | {src_ip: .src_ip, dst_ip: .dest_ip, port: .dest_port, proto: .app_proto, flow_id: .flow_id}' "$eve" | jq -s 'group_by(.port) | map({port: .[0].port, proto: .[0].proto, count: length, sources: [.[].src_ip] | unique})'
```

**Suspicious patterns:**
- SMB/RDP outside expected internal ranges
- SSH from workstations
- Database protocols (MySQL, PostgreSQL) from unexpected hosts
- Custom/unknown protocols

**Report format:**
- Protocol or port number
- Source and destination IPs
- Frequency
- Sample flow_id

## Hunt 7: Beaconing Detection

**Objective**: Identify C2 beaconing via periodic connections

```bash
# Repeated connections to same destination (potential beaconing)
jq -r 'select(.event_type=="flow") | "\(.src_ip) \(.dest_ip):\(.dest_port)"' "$eve" | sort | uniq -c | sort -rn | head -20
```

**Beaconing indicators:**
- Same src → dst:port combinations repeated 10+ times
- Regular time intervals between connections
- Small data transfers (check and response)
- Connections to uncommon ports

**Follow-up analysis:**
```bash
# Examine flows between specific hosts
jq 'select(.event_type=="flow" and .src_ip=="<SRC>" and .dest_ip=="<DST>") | {timestamp: .timestamp, bytes_to: .flow.bytes_toserver, bytes_from: .flow.bytes_toclient, duration: .flow.age}' "$eve"
```

**Report format:**
- Source IP (potentially compromised)
- Destination IP and port
- Number of connections
- Pattern analysis (regular intervals, similar sizes)

## Hunt 8: TLS/SSL Anomalies

**Objective**: Identify suspicious encrypted connections

```bash
# Self-signed or unusual certificates
jq 'select(.event_type=="tls" and .tls.issuerdn and (.tls.issuerdn | test("Self-signed|Unknown|localhost"))) | {sni: .tls.sni, issuer: .tls.issuerdn, subject: .tls.subject, src_ip: .src_ip, dst_ip: .dest_ip, flow_id: .flow_id}' "$eve"

# TLS to IP addresses (no SNI or IP-based SNI)
jq 'select(.event_type=="tls" and ((.tls.sni // "" | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) or (.tls.sni == null))) | {dst_ip: .dest_ip, src_ip: .src_ip, issuer: .tls.issuerdn, flow_id: .flow_id}' "$eve"

# Unusual JA3 fingerprints (if available)
jq -r 'select(.event_type=="tls" and .tls.ja3.hash) | .tls.ja3.hash' "$eve" | sort | uniq -c | sort -n | head -10
```

**Suspicious indicators:**
- Self-signed certificates in external connections
- TLS connections to IP addresses
- Certificates with suspicious subjects/issuers
- Rare JA3 fingerprints (non-standard TLS clients)

**Report format:**
- SNI/destination
- Certificate details
- Source IP
- Anomaly type
- Flow_id

## Hunt 9: Internal Reconnaissance

**Objective**: Detect scanning and internal reconnaissance

```bash
# Hosts connecting to many destinations (potential scanning)
jq -r 'select(.event_type=="flow") | "\(.src_ip) \(.dest_ip):\(.dest_port)"' "$eve" | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Failed connection attempts (if available in flow.state)
jq 'select(.event_type=="flow" and .flow.state and (.flow.state | test("closed|timeout|reset"))) | {src_ip: .src_ip, dst_ip: .dest_ip, port: .dest_port, state: .flow.state}' "$eve" | jq -s 'group_by(.src_ip) | map({source: .[0].src_ip, failed_conns: length, targets: [.[].dst_ip] | unique | length})'
```

**Scanning indicators:**
- Single host connecting to many destinations
- High ratio of failed connections
- Connections to multiple sequential ports
- SMB/RDP scanning within the network

**Report format:**
- Source IP (potential scanner)
- Number of unique destinations
- Ports targeted
- Success/failure ratio

## Hunt 10: HTTP Method Anomalies

**Objective**: Identify suspicious HTTP methods and paths

```bash
# Unusual HTTP methods
jq -r 'select(.event_type=="http" and .http.http_method and (.http.http_method | test("PUT|DELETE|CONNECT|TRACE|OPTIONS"))) | {method: .http.http_method, url: .http.url, hostname: .http.hostname, src_ip: .src_ip, flow_id: .flow_id}' "$eve"

# Access to admin/config paths
jq -r 'select(.event_type=="http" and .http.url and (.http.url | test("admin|config|phpmyadmin|login|wp-admin|console|manager"))) | {url: .http.url, hostname: .http.hostname, method: .http.http_method, status: .http.status, src_ip: .src_ip, flow_id: .flow_id}' "$eve"

# SQL injection or path traversal patterns
jq -r 'select(.event_type=="http" and .http.url and (.http.url | test("(union|select|\\.\\.|\\/\\/|exec|script)"))) | {url: .http.url, hostname: .http.hostname, src_ip: .src_ip, flow_id: .flow_id}' "$eve"
```

**Report format:**
- HTTP method and URL
- Target hostname
- Source IP
- Response status (if available)
- Flow_id

# Phase 3: Report Generation

After executing relevant hunts, compile findings into a structured report:


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
  "Report"            "hunt-generic-report.md" \
  "Artifacts"         "<n> files in artifacts/"
```

## Threat Hunting Report Template

```
# Network Threat Hunting Report

**Analysis Period:** [timestamp range from data]
**Total Events Analyzed:** [event count]
**Data Source:** [EVE JSON path]

## Executive Summary
[Brief overview of key findings - compromised hosts, threat categories, severity]

## Critical Findings

# 1. [Threat Category - e.g., "Malware C2 Communication"]
**Severity:** Critical/Major
**Affected Hosts:** [list of internal IPs]
**Description:** [What was detected]
**Evidence:**
- Flow IDs: [list]
- Indicators: [IPs, domains, user agents]
**Recommendation:** [Immediate actions needed]

[Repeat for each critical finding]

## Detailed Hunting Results

# High-Severity Alerts (Hunt 1)
[If alerts found, detail them]
- No alerts detected / [Number] alerts detected
- [Details with flow_ids]

# Suspicious HTTP to IP Addresses (Hunt 2)
[Report findings]
- Hosts under attack: [internal IPs making connections]
- Suspicious destinations: [external IPs]
- User agents: [list]
- Flow IDs: [list for investigation]

# Suspicious TLD Connections (Hunt 3)
[Report findings]
- Domains contacted: [list]
- Affected hosts: [internal IPs]
- Flow IDs: [list]

# Data Exfiltration Candidates (Hunt 4)
[Report findings]
- Large transfers detected: [Yes/No]
- [Details if found]

# DNS Anomalies (Hunt 5)
[Report findings]

# Beaconing Activity (Hunt 7)
[Report findings]

[Continue for all executed hunts]

## Network Baseline
- Protocol distribution: [HTTP: X%, TLS: Y%, DNS: Z%]
- Top talkers: [Most active internal IPs]
- External connections: [Number of unique external IPs]

## Recommendations

**Immediate Actions:**
1. [Isolate compromised hosts]
2. [Block malicious IPs/domains]
3. [Investigate specific flow_ids]

**Follow-up Investigation:**
1. [Deep dive into specific flows]
2. [Check endpoint logs]
3. [Review firewall rules]

**Hunting Queries Used:**
[List the hunt queries executed for reproducibility]
```

Write it to `$report_dir/hunt-generic-report.md`. Every supporting file each hunt
produced — one CSV per hunt that returned rows, plus `iocs.csv` — goes in
`$report_dir/artifacts/`, then hash the lot:

```bash
cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt
```

# Phase 4: Terminal sum-up and raw evidence — required

Writing the report file is not delivery. **Every run ends with three things printed to the
terminal**, after the folder path is named: a summary table, a prose sum-up, and at least
two verbatim log excerpts. See *Step 6* in the master skill for the full
rules.

**1. A summary table.** A compact `| Item | Value |` table rendered with `printf` so the
columns align — the report file is the record, this table is what the reader actually sees.
One screen, carrying at minimum: verdict, affected internal host(s), attacker
infrastructure, the headline counts and percentages, the activity window, which of the ten
hunts returned rows, whether any Suricata signature fired, and the case folder path with
the report filename and artifact count. Every value must already appear in the report file.

**2. Sum-up.** Short prose: the verdict first — compromised or not, which hosts, the
headline numbers, what needs action today. Name what you assessed and dismissed as benign,
so the reader knows it was examined rather than missed. Found nothing? Say so plainly and
say what was ruled out. Every figure in the sum-up must already appear in the report file.

**3. At least two verbatim log excerpts.** Raw JSON copied from command output you actually
ran — never retyped, reconstructed, or paraphrased. Print the `jq`/`grep` line above each
one so the reader can re-run it. Choose the records that carry the finding alone (the
tunnel response holding the payload, the flow with the exfil byte count, the alert with its
`flow_id`), keep `timestamp`/`flow_id`/`src_ip`/`dest_ip` in them, and mark any truncation
of a long field explicitly as `…[truncated]`. Where there are several distinct findings,
evidence them separately — the same beacon shown twice is one piece of evidence.

These excerpts often hold the most sensitive content in the log. They go to this terminal
and nowhere else; see *Data handling* at the top.


### Pretty-print the report to the terminal

Raw Markdown in a terminal is not a delivery. Render the report with the bundled printer
(no Markdown viewer required):

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-generic-report.md"
```

Colour is automatic — ANSI on a TTY, plain text when redirected, so `> out.txt` never
captures escape codes. Width follows `$COLUMNS` (cap 118); `--width N` and `--no-color`
override. Tables too wide for a grid become one labelled block per row, which is what
keeps long URLs, SNIs and query names untruncated as this routine requires.



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

**Start here:** `hunt-generic-report.md` — the full findings, including whatever was assessed as benign.
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
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-generic-report.md"
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
| `$report_dir/hunt-generic-report.md` and `README.md` | Ad-hoc Python/`jq` scripts written to run one pass |
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

- [ ] Report written to `$report_dir/hunt-generic-report.md`
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
