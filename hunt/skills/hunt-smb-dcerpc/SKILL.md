---
name: hunt-smb-dcerpc
description: "Hunt for malicious SMB / DCERPC activity in Suricata eve.json. Starts from event_type:flow where app_proto is smb or dcerpc and pivots on flow.tx_cnt (high counts = automated abuse), then correlates each flow_id to event_type:smb and event_type:dcerpc records for status codes and RPC interfaces. Detects EternalBlue/MS17-010 SMBv1 exploitation (NT_TRANS access-denied grooming), PsExec-style admin-share (C$) payload writes, credential brute-force / password spray (SESSION_SETUP logon failures), share enumeration, DCSync (DRSUAPI DRSGetNCChanges), NETLOGON abuse (Zerologon-class), RPC coercion (PetitPotam/PrinterBug/DFSCoerce), endpoint-mapper recon, service-control and scheduled-task lateral movement, and SMB2 named-pipe hammering. Surfaces tx_cnt>100 with STATUS_ACCESS_DENIED / STATUS_LOGON_FAILURE. Prints a structured report with an evidence table. Use when asked to hunt SMB/DCERPC/RPC threats, lateral movement, SMB brute-force, EternalBlue, DCSync, or Windows-protocol abuse in a Suricata log."
argument-hint: "[path to eve.json, default: eve.json in current directory] [optional: report_dir — case folder, default: report-<case>-hunt-smb-dcerpc-<date> beside the log] [tx_cnt threshold, default: 100]"
allowed-tools: "Bash, Read, Write, Glob"
---

# Hunt Malicious SMB / DCERPC in Suricata eve.json

## Data handling — read before reporting

**Nothing derived from this log leaves the machine unless the user explicitly asks for
that specific act, in that specific message.** A request to hunt, analyse, or "write up
the findings" is not approval to publish. Ask first, name the destination and what would
be sent, and wait for a yes.

Never do any of these on your own initiative: publishing an **Artifact** or any hosted
HTML report; submitting file hashes, share paths, IPs or account names to VirusTotal, a
sandbox, or any threat-intel service; posting to Slack, Teams, email or a ticketing
system; `git push`, gists, pastebins; `curl`/`wget` POST, `scp`, webhooks — including
through MCP tools.

**This routine is unusually disclosive even by hunt standards.** SMB and DCERPC findings
name internal hosts, shares, domain controllers, service accounts and the usernames seen
in failed logons — an inventory of the customer's Active Directory and a ready-made
target list. Treat account names and share paths as sensitive in every report you write,
and never send them anywhere.

**Do not touch the hosts in the log.** No SMB connection, share enumeration, port scan,
or authentication attempt against any address found here — not to confirm a finding, not
to "check if the share still exists". Everything this hunt needs is already in the
recorded transactions, and probing is both disclosive and potentially unauthorised
activity on the customer's network.

**Deliver locally:** print the report to the terminal, or write it beside the log and
tell the user the path. That is the finished deliverable.

**Always end with a terminal sum-up and raw evidence.** Naming the file path is not
delivery. After writing the report, print to the terminal (a) a short prose sum-up leading
with the verdict — compromised or not, which hosts, the headline numbers, what needs action
today, and what you assessed as benign — and (b) **at least two verbatim log excerpts**
copied from command output you actually ran, each with the `jq`/`grep` line above it so the
reader can re-run it. Never retype or reconstruct an excerpt; mark any truncation of a long
field as `...[truncated]`; keep `timestamp`/`flow_id`/`src_ip`/`dest_ip` in it. Evidence
distinct findings separately. See *Step 6* in the master skill. These excerpts are often the
most sensitive content in the log — terminal only, same as everything else here.

Detect, correlate, and report Windows file-sharing (SMB) and remote-procedure-call
(DCERPC/MSRPC) abuse from a Suricata `eve.json` log. The hunt is **flow-anchored**:
`event_type:flow` gives a per-session `flow.tx_cnt` (number of protocol transactions),
which is the single best cheap signal for "this session did something automated / abusive".
High `tx_cnt` sessions are then joined by `flow_id` to the `event_type:smb` and
`event_type:dcerpc` records, where the **SMB command + status code** and the
**RPC interface UUID + opnum** reveal exactly which technique ran.

Archetypes covered:

| # | Archetype | Primary signal | MITRE ATT&CK |
|---|---|---|---|
| 1 | **EternalBlue / MS17-010** | SMBv1 `NT_TRANS` + `NT_TRANS_SECONDARY`, `status=5` grooming | T1210 Exploit Remote Svc |
| 2 | **PsExec-style lateral move** | `WRITE_ANDX`/`CREATE` to `\\host\C$` (+ SVCCTL) | T1021.002 / T1570 |
| 3 | **Credential brute-force / spray** | many `SESSION_SETUP` → `STATUS_LOGON_FAILURE` | T1110 |
| 4 | **Share enumeration** | `TREE_CONNECT` to `C$`/`ADMIN$`/`SYSVOL`/`IPC$`, `ACCESS_DENIED` | T1135 |
| 5 | **DCSync** | DCERPC **DRSUAPI** `DRSGetNCChanges` (opnum 3) | T1003.006 |
| 6 | **Zerologon / NETLOGON abuse** | hundreds–thousands of **NETLOGON** requests in one flow | T1210 / CVE-2020-1472 |
| 7 | **RPC coercion** | **EFSR**/**MS-RPRN**/**DFSNM**/**FSRVP** binds (PetitPotam/PrinterBug) | T1187 Forced Auth |
| 8 | **Endpoint-mapper recon** | **EPM** `ept_map` on `:135` before a dynamic-port RPC | T1046 |
| 9 | **Service / task exec** | **SVCCTL**, **ATSVC/TSCH** binds + create calls | T1543.003 / T1053.005 |
| 10 | **Named-pipe hammering** | SMB2 `IOCTL`+`CREATE`+`CLOSE` loops, `tx_cnt` in the thousands | recon / coercion |

## Arguments

- `eve_path` — Path to `eve.json` (default: `eve.json` in working directory)
- `report_dir` — Case report folder (default: `report-<case>-hunt-smb-dcerpc-<YYYYMMDD-HHMM>` beside `eve.json`).
  The report goes in its root; every CSV and IOC list goes in `artifacts/`. See *Output layout* below.
- `tx_threshold` — `flow.tx_cnt` cutoff for "high" (default: `100`)

---

## Output layout — the case report folder

**Every file this routine produces goes in one case folder. Nothing is written anywhere
else, and nothing is written next to the log loose.**

```bash
eve_dir=$(cd "$(dirname "$eve")" && pwd)
case_name=$(basename "$eve" | sed 's/[-_.]\?eve.*$//; s/\.json$//')
[ -n "$case_name" ] || case_name=case
report_dir="${report_dir:-$eve_dir/report-${case_name}-hunt-smb-dcerpc-$(date +%Y%m%d-%H%M)}"
mkdir -p "$report_dir/artifacts"
plugin_dir="<the hunt plugin root you loaded this SKILL.md from>"   # holds tools/mdpretty.py
```

| Path | Contents |
|---|---|
| `$report_dir/hunt-smb-dcerpc-report.md` | The full written report |
| `$report_dir/README.md` | Handling warning for whoever opens this folder later — **required**, see below |
| `$report_dir/artifacts/` | **Everything else**: `high_tx_flows.csv`, `smb_events.csv`, `dcerpc_events.csv`, `interface_uuid_map.csv`, `iocs.csv`, `sha256sums.txt` |

- **Naming:** `report-<case>-hunt-smb-dcerpc-<YYYYMMDD-HHMM>`. The minute-resolution timestamp
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


## Step 1 — Locate, size, and confirm the schema

```bash
wc -l eve.json
grep '"event_type":"flow"' eve.json | grep -oE '"app_proto":"(smb|dcerpc)"' | sort | uniq -c
grep -c '"event_type":"smb"'    eve.json
grep -c '"event_type":"dcerpc"' eve.json
grep -m1 '"event_type":"flow"' eve.json | grep '"app_proto":"smb"' | python3 -m json.tool | head -40
grep -m1 '"event_type":"smb"'    eve.json | python3 -m json.tool
grep -m1 '"event_type":"dcerpc"' eve.json | python3 -m json.tool
```

**Field reference**

Field lists below are the full set observed in Suricata SMB/DCERPC output. Any field may
be absent on a given record (it depends on the command, the dialect, and whether NTLM/
Kerberos/DCERPC-over-pipe was used in that transaction).

### Top-level fields (present on smb / dcerpc / alert records alike)
`timestamp`, `flow_id` (**join key** to `event_type:flow`), `pcap_cnt`, `event_type`,
`src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `ip_v`, `pkt_src`, `tx_id`
(SMB records only), and `app_proto` (on flow/alert; implied on smb/dcerpc records —
report as `"smb"` / `"dcerpc"`).

### `event_type:flow` (the anchor)
- `app_proto` — `"smb"` or `"dcerpc"` (`"krb5"` / `"ntlm"` may accompany on the same host).
- `flow.tx_cnt` — **transactions in the session** — the primary hunt pivot.
- `flow.pkts_toserver` / `flow.pkts_toclient`, `flow.bytes_toserver` / `flow.bytes_toclient`.
- `flow.start`, `flow.end`, `flow.age`, `flow.state`, `flow.reason`, `flow.alerted`.

### `event_type:smb` — `smb.*`
Core / session:
- `smb.id` — internal SMB transaction id.
- `smb.command` — e.g. `SMB2_COMMAND_TREE_CONNECT`, `SMB1_COMMAND_NT_TRANS`,
  `SMB2_COMMAND_IOCTL`, `SMB2_COMMAND_CREATE`/`CLOSE`/`WRITE`/`READ`/`SESSION_SETUP`.
- `smb.status` / `smb.status_code` — **key field**: `STATUS_SUCCESS`, `STATUS_ACCESS_DENIED`,
  `STATUS_LOGON_FAILURE`, `STATUS_BAD_NETWORK_NAME`, or raw `"5"` (Win32 `ERROR_ACCESS_DENIED`).
- `smb.session_id`, `smb.tree_id`.

Negotiation / capabilities:
- `smb.dialect` (e.g. `NT LM 0.12`, `2.10`, `3.11`), `smb.client_dialects[]`.
- `smb.client_guid`, `smb.server_guid`, `smb.max_read_size`, `smb.max_write_size`.

Tree / share / pipe:
- `smb.share` — e.g. `\\host\C$`, `\\host\SYSVOL`, `\\host\IPC$`.
- `smb.share_type` — `FILE`, `PIPE`, `PRINT`.
- `smb.named_pipe` — pipe name (e.g. `\srvsvc`, `\lsarpc`, `\samr`, `\netlogon`).
- `smb.service.request` / `smb.service.response`, `smb.function`.

File operations:
- `smb.filename`, `smb.fuid`, `smb.directory`, `smb.disposition`, `smb.access`, `smb.size`.
- `smb.created`, `smb.accessed`, `smb.modified`, `smb.changed` (timestamps).

Authentication identity (**attacker attribution**):
- `smb.ntlmssp.user`, `smb.ntlmssp.domain`, `smb.ntlmssp.host`, `smb.ntlmssp.version`.
- `smb.request.native_os` / `smb.request.native_lm`, `smb.response.native_os` / `.native_lm`.
- `smb.kerberos.realm`, `smb.kerberos.snames[]` (SPNs requested).

Embedded DCERPC (RPC-over-SMB **named pipe** — RPC carried inside SMB, not on a TCP port):
- `smb.dcerpc.request` / `smb.dcerpc.response`, `smb.dcerpc.call_id`, `smb.dcerpc.opnum`.
- `smb.dcerpc.interfaces[].{uuid,version,ack_result,ack_reason}` — **bound RPC interface** (see UUID map).
- `smb.dcerpc.req.{frag_cnt,stub_data_size}`, `smb.dcerpc.res.{frag_cnt,stub_data_size}`.
  > Attacks like DCSync, SAMR/LSARPC enum, SVCCTL and the coercion RPCs frequently ride
  > over the named pipe — so **also inspect `smb.dcerpc.interfaces[].uuid`**, not only the
  > standalone `event_type:dcerpc` records.

### `event_type:dcerpc` — `dcerpc.*` (RPC over its own TCP port, e.g. :135 or 49xxx)
- `dcerpc.request` — `BIND`, `ALTER_CONTEXT`, `REQUEST`; `dcerpc.response` — `BINDACK`, `RESPONSE`, `FAULT`.
- `dcerpc.interfaces[].{uuid, version, ack_result}` — **the bound RPC interface UUID** (see map below);
  `ack_result` `0`=accept, `2`=provider-rejection, `3`=negotiate-ack.
- `dcerpc.req.{opnum, frag_cnt, stub_data_size}` — **`opnum` pinpoints the exact call** (e.g. DRSUAPI opnum 3 = DCSync).
- `dcerpc.res.{frag_cnt, stub_data_size}`.
- `dcerpc.call_id`, `dcerpc.rpc_version`.

### `event_type:alert` where `app_proto` is `smb` or `dcerpc`
> **Not present in this capture** — it has 0 alert events (`fast.log` is empty; the sensor
> ran without rules loaded). Schema documented here for completeness / other datasets.

When a rule fires on an SMB/DCERPC flow, Suricata emits an `alert` record that carries the
signature **plus the app-layer metadata** for the transaction:
- `alert.action` (`allowed`/`blocked`), `alert.gid`, `alert.signature_id`, `alert.rev`,
  `alert.signature` (rule msg), `alert.category`, `alert.severity`, `alert.metadata{}`
  (rule metadata: `mitre_technique_id`, `cve`, etc. when set), and — if configured —
  `alert.source` / `alert.target`.
- `app_proto` — `"smb"` or `"dcerpc"` (top-level on the alert).
- The **same `smb{}` or `dcerpc{}` metadata sub-object** described above (the command/status
  or interface/opnum that the alert triggered on), plus `tx_id`.
- The `flow{}` object when `eve-log → alert → metadata`/`flow` is enabled (gives `flow.tx_cnt`,
  bytes, age at alert time — the same pivots used elsewhere in this skill).
- Correlate an alert back to the full session with `flow_id`, exactly as with smb/dcerpc records.

---

## Step 2 — SMB status codes that matter

Access-denied appears in **three** forms — match all of them:

```python
DENIED = {'STATUS_ACCESS_DENIED', '5', 'STATUS_LOGON_FAILURE',
          'STATUS_ACCOUNT_DISABLED', 'STATUS_ACCOUNT_LOCKED_OUT',
          'STATUS_PASSWORD_EXPIRED', 'STATUS_WRONG_PASSWORD',
          'SRV_BADUID', 'STATUS_NETWORK_SESSION_EXPIRED'}
```
- `"5"` = Win32 `ERROR_ACCESS_DENIED` (Suricata emits the bare numeric for some SMB1/DCERPC paths).
- `STATUS_ACCESS_DENIED` (`0xC0000022`) — share/object access refused.
- `STATUS_LOGON_FAILURE` (`0xC000006D`) — **authentication failed** → brute-force / spray.

Other high-value statuses: `STATUS_BAD_NETWORK_NAME` (probing non-existent shares),
`STATUS_ACCOUNT_LOCKED_OUT` (spray tripped lockout), `STATUS_MORE_PROCESSING_REQUIRED`
(normal NTLM handshake continuation — not an error).

---

## Step 3 — DCERPC interface UUID → attack map

The **interface UUID** in `dcerpc.interfaces[].uuid` tells you what an RPC session is for.
Keep this map; it converts opaque binds into named techniques.

| UUID | Interface | Abuse / tooling |
|---|---|---|
| `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | **DRSUAPI** (MS-DRSR) | **DCSync** — opnum 3 `DRSGetNCChanges` dumps secrets |
| `12345678-1234-abcd-ef00-01234567cffb` | **NETLOGON** (MS-NRPC) | **Zerologon** (CVE-2020-1472); opnum 26 `NetrServerAuthenticate3`, 30 `NetrServerPasswordSet2` |
| `12345778-1234-abcd-ef00-0123456789ab` | **LSARPC** (MS-LSAD) | LSA policy / secrets / SID lookups (recon) |
| `12345778-1234-abcd-ef00-0123456789ac` | **SAMR** (MS-SAMR) | user / group / RID enumeration |
| `12345678-1234-abcd-ef00-0123456789ab` | **MS-RPRN** (spoolss) | **PrinterBug** coercion; **PrintNightmare** (opnum `RpcAddPrinterDriverEx`) |
| `76f03f96-cdfd-44fc-a22c-64950a001209` | **MS-PAR** (print async) | PrintNightmare variant |
| `c681d488-d850-11d0-8c52-00c04fd90f7e` | **MS-EFSR** (EFSRPC) | **PetitPotam** forced auth (`EfsRpcOpenFileRaw`, opnum 0) |
| `df1941c5-fe89-4e79-bf10-463657acf44d` | **MS-EFSR** (alt binding) | PetitPotam variant |
| `4fc742e0-4a10-11cf-8273-00aa004ae673` | **MS-DFSNM** | **DFSCoerce** forced auth |
| `a8e0653c-2744-4389-a61d-7373df8b2292` | **MS-FSRVP** | **ShadowCoerce** forced auth |
| `367abb81-9844-35f1-ad32-98f038001003` | **SVCCTL** (MS-SCMR) | remote **service** create/start → PsExec-style exec |
| `86d35949-83c9-4044-b424-db363231fd0c` | **ATSVC / ITaskSchedulerService** | **scheduled task** lateral movement |
| `338cd001-2244-31f1-aaaa-900038001003` | **WINREG** (MS-RRP) | remote registry (recon / persistence) |
| `4b324fc8-1670-01d3-1278-5a47bf6ee188` | **SRVSVC** | `NetShareEnum` share enumeration |
| `6bffd098-a112-3610-9833-46c3f87e345a` | **WKSSVC** | workstation enum |
| `8bc3f05e-d86b-11d0-a075-00c04fb68820` | **IWbemLevel1Login** (WMI) | WMI remote exec (T1047) |
| `e1af8308-5d1f-11c9-91a4-08002b14a0fa` | **EPM** (endpoint mapper) | `ept_map` recon on `:135` — resolves the above to dynamic ports |

```python
RPC_IFACE = {
 'e3514235-4b06-11d1-ab04-00c04fc2dcd2':'DRSUAPI (DCSync)',
 '12345678-1234-abcd-ef00-01234567cffb':'NETLOGON (Zerologon)',
 '12345778-1234-abcd-ef00-0123456789ab':'LSARPC',
 '12345778-1234-abcd-ef00-0123456789ac':'SAMR',
 '12345678-1234-abcd-ef00-0123456789ab':'MS-RPRN spoolss (PrinterBug/PrintNightmare)',
 '76f03f96-cdfd-44fc-a22c-64950a001209':'MS-PAR (PrintNightmare)',
 'c681d488-d850-11d0-8c52-00c04fd90f7e':'MS-EFSR (PetitPotam)',
 'df1941c5-fe89-4e79-bf10-463657acf44d':'MS-EFSR (PetitPotam)',
 '4fc742e0-4a10-11cf-8273-00aa004ae673':'MS-DFSNM (DFSCoerce)',
 'a8e0653c-2744-4389-a61d-7373df8b2292':'MS-FSRVP (ShadowCoerce)',
 '367abb81-9844-35f1-ad32-98f038001003':'SVCCTL (service exec)',
 '86d35949-83c9-4044-b424-db363231fd0c':'ATSVC/TSCH (scheduled task)',
 '338cd001-2244-31f1-aaaa-900038001003':'WINREG (remote registry)',
 '4b324fc8-1670-01d3-1278-5a47bf6ee188':'SRVSVC (share enum)',
 '6bffd098-a112-3610-9833-46c3f87e345a':'WKSSVC',
 '8bc3f05e-d86b-11d0-a075-00c04fb68820':'WMI (remote exec)',
 'e1af8308-5d1f-11c9-91a4-08002b14a0fa':'EPM (endpoint mapper recon)'}
```

---

## Step 4 — First pass: tx_cnt distribution + high-tx flow set

Anchor on `event_type:flow`. Pre-filter lines with grep before `json.loads`.

```python
import json, collections
EVE = 'eve.json'; TX = 100

dist = collections.Counter(); tot = collections.Counter()
high = {}   # flow_id -> flow facts (tx_cnt > TX)
for line in open(EVE):
    if '"event_type":"flow"' not in line: continue
    if '"smb"' not in line and '"dcerpc"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'flow': continue
    ap = e.get('app_proto', '')
    if ap not in ('smb', 'dcerpc'): continue
    f = e.get('flow', {}); tx = f.get('tx_cnt')
    tot[ap] += 1
    if tx is None: continue
    b = ('>1000' if tx > 1000 else '501-1000' if tx > 500 else '101-500' if tx > 100
         else '51-100' if tx > 50 else '11-50' if tx > 10 else '1-10')
    dist[b] += 1
    if tx > TX:
        high[e['flow_id']] = {'ap': ap, 'tx': tx, 'src': e.get('src_ip'), 'dst': e.get('dest_ip'),
            'dport': e.get('dest_port'), 'bts': f.get('bytes_toserver'), 'btc': f.get('bytes_toclient'),
            'pts': f.get('pkts_toserver'), 'ptc': f.get('pkts_toclient'),
            'age': f.get('age'), 'state': f.get('state')}

print("smb/dcerpc flows:", dict(tot))
for b in ['1-10','11-50','51-100','101-500','501-1000','>1000']:
    print(f"  {b:>9}: {dist[b]}")
print("high-tx flows (>%d): %d" % (TX, len(high)))
```

**Red flags:** any bucket in `>1000`; a cluster of **identical** `tx_cnt` values across many
src→dst pairs (an automated tool run repeatedly — e.g. the `tx=120` EternalBlue signature).

---

## Step 5 — Correlate high-tx flows to SMB records

```python
DENIED = {'STATUS_ACCESS_DENIED','5','STATUS_LOGON_FAILURE','STATUS_ACCOUNT_DISABLED',
          'STATUS_ACCOUNT_LOCKED_OUT','STATUS_PASSWORD_EXPIRED','STATUS_WRONG_PASSWORD',
          'SRV_BADUID','STATUS_NETWORK_SESSION_EXPIRED'}
ADMIN_SHARES = ('C$','ADMIN$','IPC$','SYSVOL','NETLOGON')

agg = collections.defaultdict(lambda: {'n':0,'denied':0,'status':collections.Counter(),
     'cmd':collections.Counter(),'shares':collections.Counter(),'files':collections.Counter(),
     'users':collections.Counter(),'domains':collections.Counter(),'hosts':collections.Counter(),
     'dialect':collections.Counter()})
for line in open(EVE):
    if '"event_type":"smb"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'smb' or e.get('flow_id') not in high: continue
    s = e.get('smb', {}); a = agg[e['flow_id']]; a['n'] += 1
    st = str(s.get('status',''))
    a['status'][st] += 1; a['cmd'][s.get('command','')] += 1
    if st in DENIED: a['denied'] += 1
    if s.get('share'):    a['shares'][s['share']] += 1
    if s.get('filename'): a['files'][s['filename']] += 1
    if s.get('dialect'):  a['dialect'][s['dialect']] += 1
    n = s.get('ntlmssp')
    if isinstance(n, dict):
        for k in ('user','domain','host'):
            if n.get(k): a[{'user':'users','domain':'domains','host':'hosts'}[k]][n[k]] += 1

# rank SMB flows by access-denied then tx_cnt
smb_rows = sorted(((high[f], agg[f], f) for f in high if high[f]['ap']=='smb'),
                  key=lambda r: (-r[1]['denied'], -r[0]['tx']))
for info, a, fid in smb_rows[:40]:
    print(f"{info['src']:15}->{info['dst']:15}:{info['dport']} tx={info['tx']:>5} "
          f"denied={a['denied']:>4} cmds={a['cmd'].most_common(3)} shares={a['shares'].most_common(2)} "
          f"user={a['users'].most_common(1)}")
```

### 5a — EternalBlue / MS17-010 signature
SMBv1 `SMB1_COMMAND_NT_TRANS` with `status=5`, interleaved with `NT_TRANS_SECONDARY`
(fragmented transactions), plus `NT_CREATE_ANDX`/`TREE_DISCONNECT` access-denied.
The **repetition of an identical `tx_cnt`** (e.g. exactly 120) across many src→dst pairs =
automated worm/scanner. Confirm by dumping one flow's `(command,status)` histogram.

### 5b — PsExec-style lateral movement
`WRITE_ANDX` / `SMB2_COMMAND_WRITE` / `CREATE` to `\\host\C$` or `ADMIN$`, often with
`ntlmssp.user`/`domain` populated (captured credential). Pair with a DCERPC **SVCCTL** bind
(service create) on the same host to confirm remote execution.

### 5c — Brute-force / password spray
Many `SESSION_SETUP` (SMB1 `SESSION_SETUP_ANDX` / SMB2 `SESSION_SETUP`) →
`STATUS_LOGON_FAILURE`. Aggregate by src→dst; a fan-out of one src to many dst = spray,
many attempts one dst = brute-force. Watch for `STATUS_ACCOUNT_LOCKED_OUT`.

### 5d — Share enumeration
`TREE_CONNECT` to admin/DC shares (`C$`,`ADMIN$`,`IPC$`,`SYSVOL`,`NETLOGON`) with
`ACCESS_DENIED`; `SYSVOL`/`NETLOGON` targets identify a **domain controller**.

---

## Step 6 — Correlate high-tx flows to DCERPC records

```python
rpc = collections.defaultdict(lambda: {'n':0,'ifaces':collections.Counter(),
      'opnums':collections.Counter(),'reqtypes':collections.Counter()})
for line in open(EVE):
    if '"event_type":"dcerpc"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'dcerpc' or e.get('flow_id') not in high: continue
    d = e.get('dcerpc', {}); r = rpc[e['flow_id']]; r['n'] += 1
    r['reqtypes'][d.get('request') or d.get('response') or ''] += 1
    for i in (d.get('interfaces') or []):
        u = (i.get('uuid') or '').lower()
        r['ifaces'][RPC_IFACE.get(u, u)] += 1
    op = (d.get('req') or {}).get('opnum')
    if op is not None: r['opnums'][op] += 1

for info, a in sorted(((high[f], rpc[f]) for f in high if high[f]['ap']=='dcerpc'),
                      key=lambda r: -r[0]['tx']):
    named = [x for x in a['ifaces'] if not x.count('-') == 4]     # resolved names first
    print(f"{info['src']:15}->{info['dst']:15}:{info['dport']} tx={info['tx']:>5} rpc_ev={a['n']} "
          f"ifaces={a['ifaces'].most_common(3)} opnums={a['opnums'].most_common(4)}")
```

Flag: **DRSUAPI + opnum 3** (DCSync), hundreds of **NETLOGON** requests (Zerologon),
any **EFSR/MS-RPRN/DFSNM/FSRVP** bind (coercion), **SVCCTL**/**ATSVC** (exec),
**EPM** on `:135` immediately preceding a dynamic-port bind (recon → attack chain).

> Note: `dcerpc.interfaces` is populated on `BIND`/`BINDACK`; on `REQUEST` records the
> opnum lives in `dcerpc.req.opnum`. `flow.tx_cnt` counts *all* transactions, so it can
> exceed the number of logged `dcerpc` events (Suricata may not emit one per transaction).

---

## Step 7 — Pull evidence rows for the report

For each headline finding grab the `flow_id` and one representative record:

```python
# resolve a flow_id by (src,dst) among high-tx flows, then dump its (command,status) or (iface,opnum)
def flow_for(src, dst):
    return next((f for f in high if high[f]['src']==src and high[f]['dst']==dst), None)
```
Capture: `flow_id`, `app_proto`, `src→dst:port`, `flow.tx_cnt`, bytes(→ ←), `flow.age`,
denied count, and the signature (SMB command/status histogram or RPC interface/opnum).

---

## Step 8 — Print & save the report

Print to the terminal AND write to `$report_dir/hunt-smb-dcerpc-report.md`. Do **not** truncate share paths,
filenames, NTLMSSP identities, or interface UUIDs — they are the evidence.

```
╔══════════════════════════════════════════════════════════════════════════╗
║   SMB / DCERPC HUNT REPORT — high tx_cnt + Access-Denied — eve.json        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  File   : /path/to/eve.json                                               ║
║  Scope  : event_type:flow app_proto∈{smb,dcerpc}; flow.tx_cnt > N          ║
║  Volume : N smb flows | N dcerpc flows | N smb records | N dcerpc records  ║
╠══════════════════════════════════════════════════════════════════════════╣
║  VERDICT: [CONFIRMED / SUSPICIOUS] — [techniques]                          ║
╚══════════════════════════════════════════════════════════════════════════╝

── flow.tx_cnt DISTRIBUTION ────────────────────────────────────────────────
  1-10 | 11-50 | 51-100 | 101-500 | 501-1000 | >1000

── ATTACKERS → TARGETS (by total access-denied on high-tx flows) ───────────
  app_proto  src -> dst   denied  Σtx  flows

── FINDING 1..N (one per detected archetype) ───────────────────────────────
  signature, endpoints, shares/files, captured credentials, RPC interface+opnum

── EVIDENCE TABLE ──────────────────────────────────────────────────────────
| # | app_proto | src → dest:port | flow_id | flow.tx_cnt | bytes(→ ←) | age | denied | signature |

── CAPTURED CREDENTIALS / IDENTITIES (NTLMSSP) ─────────────────────────────
  user / domain / host observed on session setup

── INDICATOR CHECKLIST ─────────────────────────────────────────────────────
  [PASS/FAIL/INFO]  indicator  →  observed value

── OUTPUT ──────────────────────────────────────────────────────────────────
  <report_dir>/
    hunt-smb-dcerpc-report.md
    artifacts/  high_tx_flows.csv, smb_events.csv, dcerpc_events.csv,
                interface_uuid_map.csv, iocs.csv, sha256sums.txt
```

```python
import os
with open(os.path.join(report_dir, 'hunt-smb-dcerpc-report.md'), 'w') as f:
    f.write(report_text)      # same content printed to the terminal
```

Supporting CSVs go in `$report_dir/artifacts/`, then hash them:

```bash
cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt
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
  "Report"            "hunt-smb-dcerpc-report.md" \
  "Artifacts"         "<n> files in artifacts/"
```

---

## Indicator checklist — malicious SMB / DCERPC

| Indicator | Archetype | How to detect |
|---|---|---|
| `flow.tx_cnt > 100` on smb/dcerpc flow | All | Step 4 distribution + high set |
| Identical high `tx_cnt` repeated across src→dst pairs | Worm/scanner | group high flows by `tx_cnt` value + count distinct pairs |
| Access-denied concentration on a flow | All | `status ∈ DENIED` count per `flow_id` (incl. raw `"5"`) |
| SMBv1 `NT_TRANS` + `NT_TRANS_SECONDARY` with `status=5` | EternalBlue | per-flow `(command,status)` histogram |
| SMBv1 in use at all on `:445` | Exposure/exploit | `dialect == "NT LM 0.12"` / `SMB1_COMMAND_*` |
| `WRITE_ANDX`/`CREATE` to `\\host\C$` or `ADMIN$` | Lateral move | `smb.share` endswith admin share + write command |
| Many `SESSION_SETUP` → `STATUS_LOGON_FAILURE` | Brute-force/spray | count per src→dst; fan-out = spray |
| `STATUS_ACCOUNT_LOCKED_OUT` observed | Spray fallout | status match |
| `TREE_CONNECT` to `SYSVOL`/`NETLOGON` (DC shares) | Recon | share name → target is a DC |
| DCERPC **DRSUAPI** bind + opnum 3 (`DRSGetNCChanges`) | DCSync | UUID `e3514235…` + `req.opnum == 3` |
| Hundreds–thousands of **NETLOGON** requests in one flow | Zerologon | UUID `12345678…cffb`, high `tx_cnt`/req count |
| DCERPC **EFSR/MS-RPRN/DFSNM/FSRVP** bind | Coercion | UUID in coercion set (PetitPotam/PrinterBug/DFSCoerce) |
| DCERPC **SVCCTL** bind + create | Service exec | UUID `367abb81…` |
| DCERPC **ATSVC/TSCH** bind | Scheduled task | UUID `86d35949…` |
| DCERPC **SAMR/LSARPC** heavy enum | Recon | UUID `12345778…ac`/`…ab` with many requests |
| **EPM** `ept_map` on `:135` before dynamic-port RPC | Recon chain | UUID `e1af8308…` then same src→dst on 49xxx |
| SMB2 `IOCTL`+`CREATE`+`CLOSE` loop, `tx_cnt` in thousands | Pipe hammering | command histogram dominated by these three |
| Captured NTLMSSP `user`/`domain`/`host` | Attribution | `smb.ntlmssp.*` on session setup |
| Outbound SMB (`:445`) to a public IP | Exfil / rogue server | `dest_ip` not RFC1918 on high-tx smb flow |
| No Suricata signature fired | All | empty/absent matching `fast.log` alert |
| High tx but `state != established` / short `age` | Scan | flow closed fast with many tx = probing |
```


### Pretty-print the report to the terminal

Raw Markdown in a terminal is not a delivery. Render the report with the bundled printer
(no Markdown viewer required):

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-smb-dcerpc-report.md"
```

Colour is automatic — ANSI on a TTY, plain text when redirected, so `> out.txt` never
captures escape codes. Width follows `$COLUMNS` (cap 118); `--width N` and `--no-color`
override. Tables too wide for a grid become one labelled block per row, which is what
keeps share paths and RPC interface UUIDs untruncated as this routine requires.



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

**Start here:** `hunt-smb-dcerpc-report.md` — the full findings, including whatever was assessed as benign.
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
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-smb-dcerpc-report.md"
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
| `$report_dir/hunt-smb-dcerpc-report.md` and `README.md` | Ad-hoc Python/`jq` scripts written to run one pass |
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

- [ ] Report written to `$report_dir/hunt-smb-dcerpc-report.md`
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
