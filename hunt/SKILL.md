---
name: hunt
description: "Master threat-hunting router for Suricata EVE JSON logs. Profiles which event types and app_protos are actually present in the log, then dispatches to the specialised hunting routines under skills/ — hunt-generic (broad 10-query sweep), hunt-dns-tunnel (DNS tunnelling/exfil/C2), hunt-tls-c2 (DGA SNI, bad certs, TLS beaconing), hunt-smb-dcerpc (lateral movement, EternalBlue, DCSync, RPC coercion) — and merges their findings into one correlated report. Use when asked to hunt for threats, find C2 or beaconing, investigate data exfiltration, look for compromised or lateral-moving hosts, or run a security assessment over a Suricata log."
argument-hint: "[path to eve.json, default: eve.json in current directory] [optional: focus area — dns | tls | smb | generic | all]"
allowed-tools: "Bash, Read, Write, Glob, Grep"
---

# Suricata Threat Hunting — Master Skill

You are an expert network threat hunter. This skill is the **entry point and router**:
it profiles the log, decides which hunting routines apply, runs them, and fuses their
output into a single correlated report.

**Input is always a Suricata EVE JSON log** — JSONL, one JSON object per line. These
skills do not read capture files; if the user has only a capture, ask them to produce
an EVE JSON log from it first and stop there.

The actual hunting logic lives in the routines under `skills/`. Do not re-implement
their queries here — load and follow the routine.

---

## Data handling — the hunt stays on this machine

**Nothing derived from the log leaves this machine unless the user explicitly asks for
that specific act, in that specific message.** Ask first, name the destination and what
would be sent, and wait for a yes. Silence is not approval, and neither is a general
instruction to "produce a report", "write this up", or "make it shareable".

This is not a formality. A hunt log is evidence: it carries the customer's internal
addressing and hostnames, live attacker infrastructure, and — once a routine reconstructs
a payload — the victim's actual stolen data. Every one of those is disclosive, and some
of it tips off the actor.

Treat all of the following as publishing, and never do any of them on your own initiative:

| Channel | Examples |
|---|---|
| Hosted pages | Publishing an **Artifact**, any hosted or shared HTML report |
| Malware / URL services | VirusTotal, Hybrid Analysis, any.run, urlscan.io, Joe Sandbox |
| Threat-intel enrichment | OTX, GreyNoise, Shodan, Censys, PassiveTotal, WHOIS/RDAP lookups on attacker infrastructure |
| Paste and code hosting | Pastebin, GitHub gists, `git push`, opening a PR or issue |
| Messaging and ticketing | Slack, Teams, email, Jira, ServiceNow — including via MCP tools |
| Raw network calls | `curl`/`wget` POST or PUT, `scp`, `rsync`, webhooks, S3/object-store uploads |

**Enrichment lookups count.** Submitting a hash, domain, or IP to a third-party service
discloses that you hold it. Sandboxes and several intel platforms publish submissions,
so an actor monitoring their own infrastructure learns they have been detected — which
can trigger cleanup or destruction of evidence. If enrichment would genuinely help,
propose it and let the user decide; offline reasoning about the indicator needs no
approval.

**Reconstructed payloads are the most sensitive artefact a hunt produces.** A decoded
tunnel payload is, by definition, data an attacker was stealing. Keep it local, hash it,
describe it, and never upload it — not to a sandbox, not into a hosted report, not as an
embedded image.

**Deliver locally.** Print the report to the terminal, or write it to a file next to the
log and tell the user the path. That is the finished deliverable. If a hosted or shared
version would be genuinely useful, say so in one sentence and stop — the user asks, or it
does not happen.

**Scope of an approval.** A yes covers the one act discussed, at that destination, then
lapses. "Publish this report" is not standing permission to publish the next one, and it
is never permission to submit indicators or payloads anywhere.

**When in doubt, print it and ask.** A local file costs the user nothing; an unwanted
upload cannot be recalled.

---

## Hunting routines

| Routine | Path | Covers |
|---|---|---|
| **@hunt-generic** | `skills/hunt-generic/SKILL.md` | 10-query broad sweep: severity alerts, HTTP-to-IP with odd UAs, suspicious TLDs, large outbound transfers, DNS length/entropy, rare protocols & ports, beaconing, TLS anomalies, internal recon/scanning, HTTP method & path abuse |
| **@hunt-dns-tunnel** | `skills/hunt-dns-tunnel/SKILL.md` | TXT base64 chunked file exfiltration; dnscat2-style hex-QNAME C2 with MX/TXT/CNAME rotation; payload reconstruction and decoding; query-rate and flow-size correlation |
| **@hunt-tls-c2** | `skills/hunt-tls-c2/SKILL.md` | High-entropy / word-list DGA SNI, IP-literal and malformed SNI, high-abuse TLDs, self-signed and OpenSSL-default certificates, long-lived C2 flows (`flow.age > 300 s`), single-destination beacons, JA3/JA4 pivots |
| **@hunt-smb-dcerpc** | `skills/hunt-smb-dcerpc/SKILL.md` | Flow-anchored `tx_cnt` pivot into SMB/DCERPC: EternalBlue/MS17-010, PsExec C$ writes, password spray, share enumeration, DCSync, Zerologon, PetitPotam/PrinterBug coercion, EPM recon, SVCCTL/ATSVC exec, named-pipe hammering |

---

## Step 1 — Locate the log and open the case folder

| Situation | Action |
|---|---|
| User gave a path | Use it — set `eve="<path>"` and confirm it exists and is non-empty |
| No path given | Glob for `eve*.json` in the working directory; if exactly one, use it |
| Several candidates, or none | Ask the user which log to hunt |

```bash
eve="eve.json"          # or the path the user supplied
wc -l "$eve"
head -1 "$eve" | jq .   # sanity-check the schema
```

Every routine takes this path as its first argument.

### The case report folder — create it before hunting, never write outside it

**Every file a hunt produces goes in one case folder, and nothing goes anywhere else.**
Create it up front so no routine has to invent a path mid-run.

```bash
eve_dir=$(cd "$(dirname "$eve")" && pwd)
case_name=$(basename "$eve" | sed 's/[-_.]\?eve.*$//; s/\.json$//')   # e.g. jokerdns
[ -n "$case_name" ] || case_name=case
report_dir="$eve_dir/report-${case_name}-<skill>-$(date +%Y%m%d-%H%M)"
mkdir -p "$report_dir/artifacts"
```

| Rule | Detail |
|---|---|
| **Naming** | `report-<case>-<skill>-<YYYYMMDD-HHMM>` — e.g. `report-jokerdns-hunt-dns-tunnel-20260829-1326`. `<case>` is derived from the log filename, `<skill>` is the routine that ran (`hunt` for a multi-routine run). The minute-resolution timestamp means a re-run never overwrites a previous hunt. |
| **Location** | Beside the EVE log, not in the working directory and never inside a skills or plugin repository. Case data and skill code do not mix. |
| **Reports** | The report file(s) sit in the folder root: `<skill>-report.md`, alongside `README.md`. |
| **README** | `$report_dir/README.md` carries the handling warning for whoever opens this folder later. Required on every hunt — see *Step 6*. |
| **Artifacts** | *Everything else* goes in `artifacts/` — decoded payloads, CSV ledgers, extracted streams, IOC lists, per-minute rate series, hash manifests. Only the report and `README.md` live in the root. |
| **Integrity** | Finish by writing `artifacts/sha256sums.txt` (`cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt`) so the evidence can be shown not to have changed. |
| **Ownership** | The folder is the deliverable. Do not delete it, prune it, or "tidy" it at the end of the run — see *Step 7*. |

Pass `report_dir` down to every routine. A routine that is handed one writes into it; a
routine invoked on its own creates its own with the same convention.

`plugin_dir` is this plugin's root — the directory holding this `SKILL.md`. Substitute
the real path when you run the commands; a `SKILL.md` is read, not executed, so there is
no `$0` to derive it from. Its `tools/mdpretty.py` renders the finished report to the
terminal; see *Step 6d*.

### Scratch space is separate from the case folder

Intermediate working files — the throwaway Python passes, sorted temporaries, partial
greps — are **not** artifacts and must never be written into the case folder. Use
`mktemp`, and see *Step 7* for the cleanup contract.

```bash
tmp=$(mktemp -d)                    # never a predictable name
trap 'rm -rf "$tmp"' EXIT           # removed even if the hunt aborts
```

---

## Step 2 — Profile the data before hunting

Run one cheap pass so routine selection is evidence-based, not guesswork:

```bash
echo "=== lines ==="; wc -l < "$eve"
echo "=== event_type counts ==="; grep -o '"event_type":"[a-z_]*"' "$eve" | sort | uniq -c | sort -rn
echo "=== app_proto counts ==="; grep -o '"app_proto":"[a-z0-9_-]*"' "$eve" | sort | uniq -c | sort -rn
echo "=== alert signatures (rule msg) — unique, by volume ==="
grep '"event_type":"alert"' "$eve" \
  | jq -Rr 'fromjson?
            | [ (.alert.signature_id // 0 | tostring),
                (.alert.signature // "<no msg>") ] | @tsv' \
  | sort | uniq -c | sort -rn \
  | awk '{n+=$1; print}
         END{ if (NR==0) print "  (no alerts — ruleset absent or nothing fired)";
              else printf "  -- alerts: %d | distinct signatures: %d\n", n, NR }'
echo "=== DNS schema version ==="
jq -r 'select(.event_type=="dns") | "v\(.dns.version // 1) \(.dns.type)"' "$eve" | sort | uniq -c
```

Record the counts — they become the "Network Baseline" section of the final report,
and they tell you which routines have data to work with.

**Profile alerts by signature message.** The rule `msg:` — logged as `alert.signature`,
paired with its `signature_id` — is the only alert field that is always present, always
meaningful, and derived from what actually matched.

Read the output as a distribution, not a to-do list:

- **One signature dominating by orders of magnitude** is usually a noisy or misdeployed
  rule, not the incident — but confirm that before dismissing it.
- **A signature that fired once or twice** is often the interesting one. Low-count,
  high-specificity hits are where real intrusions show up.
- **`(no alerts)`** means the hunt is behavioural only. Say so explicitly in the report;
  it is a finding about the sensor, not a clean bill of health.

### Do not triage on alert severity

Neither severity field is evidence about the traffic, and neither belongs in a hunt's
selection criteria:

- **`alert.metadata.signature_severity`** (`Critical` / `Major` / `Minor` /
  `Informational`) is a free-text `metadata:` tag typed by the rule author. Suricata
  neither validates nor defaults it — most rulesets never set it at all, and downstream
  consumers that do fill in a default tend to assume the most severe bucket so nothing
  is silently deprioritised.
- **`alert.severity`** (numeric) is `s->prio`, taken from the rule's `priority:` keyword
  or from its `classtype`'s entry in `classification.config`. A rule that declares
  neither gets `DETECT_DEFAULT_PRIO`, which is simply a compiled-in constant.

Both therefore describe **how a rule was written**, not how dangerous the traffic is,
and `classification.config` is site-editable — so the same rule firing on the same
packet yields different severities in different environments. Filtering or ranking on
either produces false positives from ruleset and deployment differences, and false
negatives wherever the metadata is absent.

Rank by signature volume and specificity instead, and let the behavioural routines —
not a rule author's self-assessment — decide what is worth chasing.

Two mechanics in that pipeline are deliberate, and worth keeping if you adapt it:

- **`grep` prefilter before `jq`.** `jq` JSON-parses every line it is handed; `grep`
  discards the non-alert lines far more cheaply. Measured on an 800 MB log this cut the
  step from 5.4 s to 4.6 s, and the gap widens as the log grows and alerts stay sparse —
  which matters when `eve.json` is tens of GB.
- **`jq -Rr 'fromjson?'` rather than a native parse.** A live or rotating `eve.json`
  routinely ends in a half-written line. Native `jq` prints a parse error and exits
  non-zero on it; `fromjson?` skips the malformed line, exits 0, and keeps the profile
  output clean. Verified against a log with a truncated final record.

**The DNS schema version is not cosmetic — it changes where the query name lives.** Read
it before running any DNS query, and see *DNS EVE schema versions* under Operating notes
for the field map and the copy-paste compatibility helpers. A version-specific query run
against the wrong version returns **zero rows and reads exactly like a clean result**.

---

## Step 3 — Choose the hunt

Present the routines below to the user with the Step 2 profile alongside them, mark the
ones that have data, and ask which to run. Offer **all applicable** as the default.

If the user already named a focus in their request (`dns`, `tls`, `smb`, `generic`, or
`all`), skip the question and run that selection directly.

---

### 1. Generic threats — `@hunt-generic`

*Applicable to: any EVE log. Always offer this one.*

Use `@hunt-generic` skill for structured threat hunting methodologies for detecting:
- Malware C2 (Command & Control) communications
- Data exfiltration attempts
- Suspicious user agents and connection patterns
- Domain generation algorithms (DGA)
- Malicious TLDs and hosting infrastructure
- Lateral movement and reconnaissance
- Protocol anomalies and evasion techniques

### 2. DNS-based attacks — `@hunt-dns-tunnel`

*Applicable when: `event_type:dns` is present — especially with TXT/MX/CNAME records or
long QNAMEs.*

Use `@hunt-dns-tunnel` skill for structured threat hunting methodologies for detecting:
- DNS tunnel
- DNS exfiltration
- DNS Command and Control (C2)
- DNS generic detection of dnscat / iodine / TXT
- Reconstruction and decoding of the tunnelled payload

### 3. Windows network threats — `@hunt-smb-dcerpc`

*Applicable when: `app_proto` includes `smb` or `dcerpc`.*

Use `@hunt-smb-dcerpc` skill for structured threat hunting methodologies for detecting:
- EternalBlue / MS17-010 SMBv1 exploitation
- PsExec-style admin-share (C$) payload writes
- Credential brute-force / password spray (SESSION_SETUP logon failures)
- Share enumeration
- DCSync (DRSUAPI DRSGetNCChanges)
- NETLOGON abuse (Zerologon-class)
- RPC coercion (PetitPotam/PrinterBug/DFSCoerce)
- Endpoint-mapper recon
- Service-control and scheduled-task lateral movement
- SMB2 named-pipe hammering

### 4. TLS / encrypted threats — `@hunt-tls-c2`

*Applicable when: `event_type:tls` is present.*

Use `@hunt-tls-c2` skill for structured threat hunting methodologies for detecting:
- High-entropy / random-alnum SNI
- DGA-hex label + cheap TLS TLD
- Word-DGA CN on junk TLD
- IP-literal and malformed SNI, high-abuse TLDs
- Self-signed and OpenSSL-default certificates
- TLS C2 beaconing and exfiltration (long-lived flows, single-destination repetition)
- JA3 / JA4 fingerprint pivots

### 5. All applicable — recommended default

Run `@hunt-generic` first, then every specialised routine whose protocol appears in the
Step 2 profile. Order them by the severity of their initial signal — hunt the loudest
thing first.

---

## Step 4 — Run each selected routine

For each routine: read its `SKILL.md`, pass it the EVE path (and its own optional
arguments — output file, thresholds), and follow its steps in order. Each routine
writes its own report file; keep those paths for Step 5.

**Escalation — a generic hit promotes a specialised routine.** If `hunt-generic`
surfaces a lead, follow it into the deeper routine even when that protocol looked quiet
in the profile and the user did not pick it. Tell the user you are adding the routine
and why:

- Hunt 3 (suspicious TLD) or Hunt 8 (TLS anomaly) hits → run `@hunt-tls-c2`
- Hunt 5 (long / high-entropy DNS) hits → run `@hunt-dns-tunnel`
- Hunt 9 (internal recon) hits, or SMB alerts → run `@hunt-smb-dcerpc`
- Hunt 7 (beaconing) hits → run whichever routine matches the beacon's `app_proto`

**Batch the Bash.** Every routine issues many `jq`/`grep` queries. Chain them into a
single Bash invocation with `;` and `echo "=== ... ==="` separators, or write a short
script to the scratchpad and run it once. Repeated single-query calls generate a
confirmation prompt each time and make hunts painful to run.

**Do not stop at the first finding.** A routine's queries are designed to be run as a
set; a quiet query is itself a result and belongs in the report.

---

## Step 5 — Correlate and report

Routines run independently but attackers do not. After the last routine, cross-reference:

1. **By IP** — does one internal host appear in DNS tunnelling *and* TLS beaconing? That
   is one compromised host, not two findings.
2. **By `flow_id`** — the join key across every event type. Always carry it into the
   report; it is what makes a finding investigable.
3. **By timeline** — order findings by first-seen. Recon → exploitation → C2 → exfil is
   a kill chain; separate spikes are probably separate incidents.
4. **By JA3/JA4 and certificate** — shared fingerprints link destinations that share no
   IP or domain.

### Report structure

```markdown
# Network Threat Hunting Report

**Source:** <file>   **Events:** <n>   **Time range:** <first> – <last>
**Routines run:** hunt-generic, hunt-dns-tunnel, ...

## Executive Summary
<2–4 sentences: was there a compromise, which hosts, what is the confidence>

## Critical Findings
### 1. <Threat category>
- **Severity:** Critical | High | Medium | Low
- **Evidence:** <specific events, counts, decoded payload>
- **Affected hosts:** <src → dst>
- **flow_ids:** <ids for pivot>
- **MITRE ATT&CK:** <technique>
- **Assessment:** <what it means, and how confident you are>

## Correlated Activity
<hosts or infrastructure appearing across multiple routines, as a kill-chain timeline>

## Per-Routine Results
<one subsection per routine, including the ones that found nothing>

## Network Baseline
<event-type / app_proto / severity counts from Step 2>

## Recommendations
<containment, then detection gaps, then further investigation>
```

**Interpret, don't dump.** A table of counts is not a finding. State what the traffic
means, name your confidence, and say plainly when something is benign — a hunt that
reports "no evidence of X" is a successful hunt.

**Deliver the report locally, into the case folder.** Write it to
`$report_dir/<skill>-report.md`, put every supporting file under `$report_dir/artifacts/`,
and name the folder path to the user. Do not publish it, host it, or send it anywhere —
see *Data handling* above. The report is finished when it is written to the case folder
**and** summarised in the terminal with a table (Step 6).

---

## Step 6 — Always sum up in the terminal, with raw evidence

**Required for every report, every routine, every time.** Writing the report file is not
delivery. A path alone forces the reader to go open a file to learn whether their network
is on fire. Three things always go to the terminal after the file is written:

### 6a. A plain summary table — always, in addition to the report file

Print a compact `| Item | Value |` table to the terminal alongside the full report file.
This is not optional and it does not replace the file: the file is the record, the table
is what the reader actually sees. Keep it to one screen.

The table always carries, at minimum:

| Row | Content |
|---|---|
| Verdict | Confirmed / suspected / clean, and the archetype or threat class |
| Victim / affected hosts | Internal IPs, one row each if few |
| Attacker infrastructure | External IPs, domains, resolvers |
| Headline volume | Event counts, percentages, byte totals — the numbers that carry the finding |
| Timing | The activity window and rate |
| Payload / artefact | Size, hash, identified type, validation result — where a routine reconstructs one |
| Detection gap | Whether any Suricata signature fired on the activity |
| Output | The case folder path, report filename, artifact count |

Render it with `printf` so the columns line up in a terminal, and lead with a boxed
verdict banner where the routine defines one. Every value in the table must already
appear in the report file — the table is a condensation, never a new claim.

### 6b. The sum-up

A short prose summary of the report — what was found, on which hosts, how bad, and what to
do first. Lead with the verdict, not the methodology. Keep it to something a reader can
take in without scrolling: the compromise, the affected hosts, the headline numbers, the
one or two things that need action today. Name any finding you assessed as benign, so the
reader knows it was examined and dismissed rather than missed. If the hunt found nothing,
say that plainly and say what was ruled out.

The sum-up is a condensation, never a new claim. Every number in it must already appear in
the report file.

### 6c. Indisputable evidence — at least two raw log excerpts

Print **two or more verbatim records straight from the EVE log** that a sceptical reader
can verify without trusting your analysis. This is the difference between an assertion and
a finding.

Rules for the excerpts:

- **Verbatim.** Real JSON, actually present in the file, copied from a command whose output
  you have seen. Never hand-typed, reconstructed from memory, summarised into prose, or
  "cleaned up". If you did not run a command that printed it, do not print it.
- **Show the command too.** One `jq`/`grep` line above each excerpt so the reader can
  re-run it and get the same bytes back. This is what makes the evidence checkable.
- **Pick the load-bearing records.** Choose the ones that carry the finding on their own:
  the tunnel response containing the encoded payload, the flow record with the exfil byte
  count, the alert with its `flow_id`, the certificate with the impossible issuer. A record
  that merely shows traffic existed proves nothing.
- **Long fields may be truncated, and say so.** Mark any cut explicitly — `…[truncated]` —
  and never truncate in a way that changes what the record means.
- **Cover distinct findings** where there is more than one. Two excerpts of the same
  beacon is one piece of evidence printed twice.
- **Carry the pivot keys.** Keep `timestamp`, `flow_id`, `src_ip`, `dest_ip` in the
  excerpt; those are what the reader needs to go look for themselves.

Prefer whole records (`jq .` on one event) over field-projected ones — the point is that
nothing was selected away. Where a whole record is unusably large, project fields with
`jq -c` and say that is what you did.

The evidence excerpts obey *Data handling* like everything else: they are printed to this
terminal and nowhere else. They frequently contain the most sensitive content in the log —
decoded payloads, internal hostnames, live attacker infrastructure — which is exactly why
they must not be pasted into a ticket, a chat, or an upload without the user asking.


### 6d. Pretty-print the report to the terminal

The report file is Markdown; raw Markdown in a terminal is not a delivery. Render it
with the bundled printer, which needs no Markdown viewer installed:

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/<skill>-report.md"
```

- **Colour is automatic**: ANSI when stdout is a TTY, clean plain text when redirected
  to a file or a pager, so `> report.txt` never captures escape codes.
- **Width** follows `$COLUMNS` (capped at 118); override with `--width N`. Force plain
  text with `--no-color`.
- **A table too wide for a grid becomes one labelled block per row.** This is why the
  printer exists rather than a generic one: the routines forbid truncating `dns.rrname`,
  `dns.rdata`, certificate subjects and share paths, and a squeezed grid cannot honour
  that.

This replaces neither the summary table (6a) nor the raw evidence excerpts (6c) — those
are printed directly, because they must be reproducible from the commands you ran.



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

**Start here:** `<skill>-report.md` — the full findings, including whatever was assessed as benign.
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


### 6e. Always pretty-print the finished report — this is the last act of every hunt

**Every hunt ends by rendering the report, without being asked.** Not a path, not a
promise, not "the report is written to X" — the rendered report itself.

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/<skill>-report.md"
```

**Make sure the user actually sees it.** Shell output is not reliably displayed to the
user — it goes to you. So after rendering, **reproduce the report in your own reply
message as Markdown**, which is what the user reads. Running the command and reporting
that you ran it is not delivery; if the user has to ask twice, the hunt was not finished.

Print `README.md` the same way when the folder is new, so the handling warning is read
rather than merely filed.


---

## Step 7 — Clean up and housekeeping

A hunt leaves two kinds of file behind. **Scratch is deleted. Evidence is kept.** Getting
that backwards either destroys the deliverable or leaves the victim's stolen data lying
around in `/tmp`. Run this at the end of every hunt, and after an aborted one.

### What is scratch, and what is evidence

| Keep — the deliverable | Delete — scratch |
|---|---|
| `$report_dir/<skill>-report.md` | Ad-hoc Python/`jq` scripts written to run one pass |
| `$report_dir/artifacts/*` — payloads, CSVs, IOC lists, hash manifest | Sorted/uniq'd intermediate files, split chunks, partial greps |
| The original `eve.json` — **never touched, never modified, never moved** | Anything under `$(mktemp -d)`, and the temp dir itself |
| Anything the user created or named | Copies of the EVE log made for convenience |

### Temp file rules

- **`mktemp` only.** Never a predictable name — no `/tmp/hunt.txt`, no `/tmp/out.$$`, no
  fixed filename in the working directory. A predictable path in a world-writable
  directory is a symlink-attack target and a collision waiting to happen between two
  concurrent hunts.
- **One temp dir per hunt**, created up front, removed on exit:

  ```bash
  tmp=$(mktemp -d) || exit 1
  trap 'rm -rf "$tmp"' EXIT INT TERM
  ```

  The `trap` matters more than the `rm`: a hunt that aborts halfway — a bad `jq`, a
  `Ctrl-C`, an out-of-memory Python pass — still cleans up.
- **Restrictive permissions.** Scratch holds decoded payloads and internal addressing on
  a possibly shared host: `chmod 700 "$tmp"` (and `umask 077` before writing anything
  sensitive).
- **Clean up after analysis, not before reporting.** Delete scratch once the report and
  artifacts are written and verified — never while a later step still needs it.

### Deletion safety — the rules that stop a cleanup becoming an incident

- **Delete only paths you created in this run.** Track them; never glob a directory you
  did not make. `rm -rf "$tmp"` is safe because `$tmp` came from `mktemp`. `rm -rf /tmp/*`
  is not, ever.
- **Never `rm -rf` an unquoted or possibly-empty variable.** `rm -rf "$tmp"` with `$tmp`
  unset targets `/`. Guard it: `[ -n "$tmp" ] && [ -d "$tmp" ] && rm -rf "$tmp"`.
- **Never delete, truncate, rewrite, re-compress or move the source `eve.json`.** It is
  the evidence the whole hunt rests on, it may be under legal hold, and the hunt is
  read-only over it by design. If it needs rotating or archiving, that is the user's call.
- **Never delete a previous case folder** to "make room" or because it looks like a
  duplicate. The timestamp in the name exists precisely so runs accumulate. If the user
  wants old hunts pruned, they will ask.
- **Look before you overwrite.** If a target path already exists, stop and pick a new
  name rather than clobbering it — the existing file may be another analyst's evidence.
- **Never run the reconstructed payload.** Write it with a `.txt` extension, never
  `chmod +x` it, never open it in a renderer, never pass it to an interpreter. Hash it,
  identify it with `file(1)`, and describe it.

### Resource housekeeping on large logs

- **Stream, never slurp.** `eve.json` is routinely tens of GB. Read line by line;
  `jq -c`/`grep`/streaming Python only. Never `jq -s`, never `json.load(open(...))`,
  never `read()` the whole file.
- **Check free space before writing a reconstructed payload**, which can be hundreds of
  MB and is written twice (raw stream plus decoded file): `df -h "$report_dir"`.
- **Prefilter with `grep` before `jq`** — `jq` parses every line it is handed; `grep`
  discards non-matching lines far more cheaply.
- **Bound anything unbounded.** Cap in-memory counters and sample lists so a hostile or
  merely enormous log cannot exhaust RAM.

### Final housekeeping checklist

Print this outcome, do not just perform it:

```bash
# 1. hash every artifact so the evidence is fixed
cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt

# 2. remove scratch, safely
[ -n "$tmp" ] && [ -d "$tmp" ] && rm -rf "$tmp"

# 3. confirm what survived
ls -la "$report_dir" "$report_dir/artifacts"
```

- [ ] Report written to `$report_dir/<skill>-report.md`
- [ ] `$report_dir/README.md` written, with the CAUTION block intact
- [ ] Report pretty-printed **and reproduced in the reply message** — not just a path
- [ ] Every supporting file in `$report_dir/artifacts/`, nothing loose elsewhere
- [ ] `artifacts/sha256sums.txt` written, covering every artifact but itself, and `sha256sum -c` passes
- [ ] Source `eve.json` unmodified — same size, same mtime, same inode
- [ ] Scratch dir removed; nothing sensitive left in `/tmp`
- [ ] No reconstructed payload is executable, and none was executed or opened
- [ ] Nothing left the machine (Step: *Data handling*)
- [ ] Summary table and evidence excerpts printed to the terminal (Step 6)
- [ ] Case folder path stated to the user

---

## Operating notes

- **Suricata EVE JSON** is JSONL — one JSON object per line. `jq -c`, `grep`, and
  streaming Python all work; never load a large `eve.json` fully into memory.
- **DNS EVE schema versions** — see the dedicated section below. Always detect the
  version first; the query name moves between versions and a mismatched query silently
  returns nothing. `app_proto` is not emitted on `dns` events — report `"dns"` from the
  event type.
- **`event_type:flow`** carries `flow.tx_cnt`, `flow.age`, `bytes_toserver`/`toclient`
  and `flow.state`. It is the cheapest source of behavioural signal and the anchor for
  the SMB routine.
- **Alert context** depends on the ruleset that was active when the log was written. If
  `event_type:alert` is absent, say so — Hunt 1 of `hunt-generic` has no data, and the
  rest of the hunt is behavioural only.
- **Temp files:** `mktemp` only, `trap`-removed on exit, never a predictable name — see
  *Step 7*. Scratch never goes in the case folder, and the case folder is never deleted.
- **The source log is read-only.** No routine ever writes to, moves, truncates or
  re-compresses `eve.json`.
- **Egress:** none. No routine in this skill set has any reason to open an outbound
  connection — every query is local `jq`/`grep`/Python over a file on disk. If you find
  yourself reaching for `curl`, an upload, or a publish step, stop and ask; see *Data
  handling*.

---

## DNS EVE schema versions

Suricata has shipped three incompatible DNS EVE layouts. Which one you get depends on
the Suricata version and on `dns.version` in `suricata.yaml` — **not** on the log's age.
v2 is the default through Suricata 7.x; v3 is the default from Suricata 8.0.

Detect it before querying:

```bash
jq -r 'select(.event_type=="dns") | "v\(.dns.version // 1) \(.dns.type)"' "$eve" | sort | uniq -c
```

`dns.version` is **absent** in v1, so `// 1` is the correct default, not a guess.

### Field map

| | **v1** (no `version` key) | **v2** (`"version":2`) | **v3** (`"version":3`) |
|---|---|---|---|
| `dns.type` values | `query` / `answer` | `query` / `answer` | `request` / `response` |
| Query name | `dns.rrname` *(flat)* | `dns.rrname` *(flat)* | `dns.queries[].rrname` |
| Query type | `dns.rrtype` *(flat)* | `dns.rrtype` *(flat)* | `dns.queries[].rrtype` |
| Answer records | **one event per RR**, `dns.rdata` / `dns.rrtype` / `dns.ttl` flat | `dns.answers[]` array | `dns.answers[]` array |
| `dns.grouped` | absent | present | present |
| `dns.authorities[]` | absent | absent | present (may be) |

Three consequences worth internalising:

1. **`dns.answers[]` is identical in v2 and v3.** Answer-side logic — TXT rdata
   extraction, payload reassembly, rdata length checks — is already portable across
   both. Only **v1** needs special handling there, because it emits one event per
   answer RR with the fields flat on `dns`.
2. **The query name is what actually breaks.** v1/v2 put it flat on `dns`; v3 nests it
   in an array. This is the single most common source of a false-clean DNS hunt.
3. **`.dns.query.rrname` (singular `query`) is not valid in any version.** If you find
   it in a query, it is a bug — it matches nothing, in every version, always.

### Compatibility helpers

**jq** — define once, reuse in every DNS query:

```bash
# Note the trailing `|| true`: `read -d ''` always exits 1 when it hits EOF, which
# aborts the script under `set -e` or breaks an && chain even though $DNSC is set fine.
read -r -d '' DNSC <<'JQ' || true
def dns_ver:        (.dns.version // 1);
def is_dns_request: (.dns.type == "request" or .dns.type == "query");
def is_dns_response:(.dns.type == "response" or .dns.type == "answer");
# One {rrname,rrtype} per query, whatever the version.
def dns_queries:
  if (.dns.queries? // null) != null then .dns.queries[]
  elif (.dns.rrname? // null) != null then {rrname: .dns.rrname, rrtype: .dns.rrtype}
  else empty end;
# One answer object per RR, whatever the version.
def dns_answers:
  if (.dns.answers? // null) != null then .dns.answers[]
  elif (.dns.rdata? // null) != null then
       {rrname: .dns.rrname, rrtype: .dns.rrtype, rdata: .dns.rdata, ttl: .dns.ttl}
  else empty end;
JQ

# Example — version-agnostic long-QNAME hunt:
jq -r "$DNSC"'
  select(.event_type=="dns" and is_dns_request)
  | dns_queries as $q
  | select(($q.rrname|length) > 40)
  | {domain:$q.rrname, rrtype:$q.rrtype, length:($q.rrname|length),
     src_ip:.src_ip, flow_id:.flow_id}' "$eve"
```

**Python** — the same contract, for the reassembly and statistics passes:

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

### Caveats that change your counts

- **v1 inflates response counts.** One event per answer RR means "number of response
  events" ≠ "number of DNS responses". Group by `flow_id` + `dns.id` before reporting
  response totals, and never derive a query rate from v1 answer events.
- **v2/v3 `dns.rrname` vs `dns.answers[].rrname` differ on CNAME chains.** The flat
  field (v2) and `queries[]` (v3) hold the *queried* name; `answers[].rrname` holds the
  name of each RR, which may be a CNAME target. For "what did the host ask for", use the
  query side; for "what came back", use the answer side.
- **A v3 log has no flat `dns.rrname` at all** — not even on responses. Any fallback
  chain must test `queries[]` first.
- **Report the version you found.** State it in the report's Network Baseline so the
  reader knows which field map the findings were built on.

Your hunting identifies active compromises, attacker infrastructure, and the detection
gaps that let them through.
