---
name: hunt-ldap
description: "Hunt for malicious LDAP / CLDAP activity in Suricata eve.json. Prefilters event_type:ldap plus the flow, anomaly and alert records for LDAP ports (389/636/3268/3269), then runs one streaming pass (bundled scripts/ldap_hunt.py) that decodes the hex SASL bind blobs — NTLMSSP domain/user/workstation, NTLMv1 vs v2, signing flag, versus Kerberos — and the binary CLDAP Netlogon responses (DC inventory, USER_UNKNOWN_EX). Detects LDAP password spray and brute force (AD 'data 52e/775' sub-codes) including spray-then-success and one identity failing from many sources, NTLM relay to LDAP (machine or DC account binding from an IP that is not that host, unsigned NTLM binds), NTLMv1, cleartext simple binds, anonymous binds followed by searches and unauthenticated operations (000004DC), compare-based password guessing, reads of secret attributes (LAPS, gMSA, BitLocker, trust keys, unicodePwd) and of Kerberoast / RBCD / shadow-credential / ADCS attack surface, directory writes (msDS-KeyCredentialLink, RBCD, SPN, noPac sAMAccountName rename, UPN / altSecurityIdentities for ESC9/10/14, DACL on the domain root or AdminSDHolder, new computer objects, privileged group changes), DirSync / DirSync_EX / SD_FLAGS / paged-result / tree-delete controls per source, StartTLS and PasswordModify extended operations, cleartext search volume per source, CLDAP user enumeration with the valid usernames it found, rogue LDAP servers and DC responders, JNDI / Log4Shell references in LDAP replies, internet CLDAP reflection probing and exposed directories, and bulk directory pulls hidden inside sealed SASL sessions. Correlates flagged hosts across protocols by IP and time. Prints a structured report with an evidence table. Use when asked to hunt LDAP, CLDAP or Active Directory directory abuse, LDAP brute force or spray, NTLM relay to LDAP, BloodHound/SharpHound-style enumeration, shadow credentials, RBCD, or DC discovery in a Suricata log."
argument-hint: "[path to eve.json, default: eve.json in current directory] [optional: report_dir — case folder, default: report-<case>-hunt-ldap-<date> beside the log] [bulk bytes threshold, default: 500000] [spray distinct-identity threshold, default: 5] [cleartext enumeration entries threshold, default: 1000]"
allowed-tools: "Bash, Read, Write, Glob, Grep"
---

# Hunt Malicious LDAP / CLDAP in Suricata eve.json

## Data handling — read before reporting

**Nothing derived from this log leaves the machine unless the user explicitly asks for
that specific act, in that specific message.** A request to hunt, analyse, or "write up
the findings" is not approval to publish. Ask first, name the destination and what would
be sent, and wait for a yes.

Never do any of these on your own initiative: publishing an **Artifact** or any hosted
HTML report; submitting IPs, domains, DNs or account names to VirusTotal, a sandbox, or
any threat-intel service; posting to Slack, Teams, email or a ticketing system;
`git push`, gists, pastebins; `curl`/`wget` POST, `scp`, webhooks — including through MCP
tools.

**LDAP is the most disclosive protocol a hunt touches.** A directory log is a map of the
customer's Active Directory: forest and domain names, every domain controller and its
site, distinguished names, user and machine account names, group membership, and — when
LDAP is unsigned — attribute values such as LAPS passwords. Treat every account name, DN
and DC hostname as sensitive in every report, and never send any of them anywhere.

**The SASL bind blobs contain crackable credential material. Never extract it.**
`ldap.request.bind_request.sasl.credentials` is the hex of the SPNEGO token: an NTLMSSP
`AUTHENTICATE` message carries the NetNTLMv1/v2 challenge-response, and a Kerberos token
carries an AP-REQ. Either can be fed to an offline cracker. The bundled script reads only
the **identity fields** (domain, user, workstation), the response **length** (to tell v1
from v2) and the flag bits — it never writes the NT/LM responses, the server challenge, or
any ticket bytes, and you must not either: no `hashcat`/`john` formatting, no "for
verification" dumps, no hex excerpts of the blob in the report. When an evidence excerpt
includes a bind record, truncate `credentials` to its first 32 hex characters and mark it
`…[truncated — credential material]`.

**Other LDAP records carry secrets in cleartext too — never quote their values.** A
`modify_request` or `add_request` on `unicodePwd` / `userPassword` holds the password being
set (a machine-account add carries its new password); a `PasswordModify` extended request
`value` holds the new and old password; a `compare_request` against `userPassword` holds the
guess; a `search_result_entry` for `ms-Mcs-AdmPwd`, `msDS-ManagedPassword` or
`msFVE-RecoveryPassword` holds the secret itself. The script records attribute **names**
only, never these values. Every evidence excerpt goes through `scripts/redact.jq`
(Step 5), which redacts all of them and the bind tokens while keeping every other field verbatim.

**Do not touch the hosts in the log.** No LDAP query, CLDAP ping, bind attempt, port
scan or `ldapsearch` against any address found here — not to confirm a finding, not to
"check whether the DC still answers". Everything this hunt needs is already in the
recorded transactions, and probing a customer's domain controller is both disclosive and
potentially unauthorised.

**Deliver locally:** print the report to the terminal, or write it beside the log and
tell the user the path. That is the finished deliverable.

**Always end with a terminal sum-up and raw evidence.** Naming the file path is not
delivery. After writing the report, print to the terminal (a) a short prose sum-up leading
with the verdict — compromised or not, which hosts, the headline numbers, what needs action
today, and what you assessed as benign — and (b) **at least two verbatim log excerpts**
copied from command output you actually ran, each with the `jq`/`grep` line above it so the
reader can re-run it. Never retype or reconstruct an excerpt; mark any truncation of a long
field as `…[truncated]`; keep `timestamp`/`flow_id`/`src_ip`/`dest_ip` in it. Evidence
distinct findings separately. See *Step 6* in the master skill. These excerpts are often the
most sensitive content in the log — terminal only, same as everything else here.

---

Detect, correlate, and report directory-service abuse from a Suricata `eve.json` log.
The hunt is **transaction-anchored with a flow backstop**: `event_type:ldap` gives the bind
identity, the search base/attributes, any writes and every result code; `event_type:flow`
covers what the parser cannot see — sealed SASL sessions, LDAPS, CLDAP datagrams that
produced no `ldap` record — through bytes, packets and cadence.

Archetypes covered:

| # | Archetype | Primary signal | MITRE ATT&CK |
|---|---|---|---|
| 1 | **Password spray / brute force** | `bind_response` `invalid_credentials`, AD `data 52e`; many identities per source = spray; **a successful bind from the same source afterwards = the spray worked**; one identity failing from many sources = distributed brute force; `data 775` = lockout | T1110.003 / T1110.001 |
| 2 | **NTLM relay to LDAP** | NTLMSSP `AUTHENTICATE` for a machine account (`X$`) arriving from an **IP that is not host X** (above all a DC's own account from a non-DC IP); machine-account NTLM without `NEGOTIATE_SIGN`; unsigned NTLM bind that **succeeds**; one identity from many IPs | T1557.001 |
| 3 | **Weak / cleartext authentication** | Simple bind with a DN (password on the wire); NTLMv1 (24-byte NT response); anonymous NTLM | T1040 / T1552 |
| 4 | **Anonymous bind + unauthenticated operations** | `bind_request` with empty name and no SASL **followed by searches that return entries** (DC allows anonymous reads); `000004DC` "a successful bind must be completed" | T1087.002 |
| 5 | **Secret-attribute reads** | Request or response attribute ∈ LAPS / gMSA / BitLocker / trust-key / `unicodePwd` set; value returned in cleartext | T1552 / T1555 |
| 6 | **AD attack-surface recon** | `servicePrincipalName`, `userAccountControl`, RBCD, `nTSecurityDescriptor`, `allowedAttributesEffective`, ADCS template attributes; `*` attribute lists; the acl + kerberoast + delegation **combination per source** | T1087.002 / T1069.002 / T1558.003 |
| 7 | **Directory writes** | `modify/add/del/mod_dn_request` on `msDS-KeyCredentialLink` (shadow credentials), RBCD, SPN, `sAMAccountName` (noPac), `userPrincipalName` / `altSecurityIdentities` (ESC9/10/14), `nTSecurityDescriptor` on the domain root or AdminSDHolder, new computer object (any OU), privileged group, GPO path / extensions | T1098 / T1484 / T1136.002 / T1068 |
| 8 | **Bulk dump controls / ext-ops** | DirSync `…4.841` / DirSync_EX `…4.2090` **from a non-DC source**, SD_FLAGS `…4.801` + paged results `…4.319` from one source, tree delete `…4.805`, ASQ, show-deleted; `PasswordModify`, `StartTLS` | T1003 / T1087.002 / T1485 |
| 9 | **CLDAP user enumeration** | Netlogon pings for many usernames from one source: opcode **23** with a user name = **valid account**, opcode **25** `USER_UNKNOWN_EX` = unknown | T1087.002 |
| 10 | **Rogue DC / LDAP server** | One DC hostname answering CLDAP from several IPs; **TCP LDAP binds sent to a host that is not a known DC** (Responder / relay listener capturing credentials) | T1557 |
| 11 | **Internet LDAP / CLDAP exposure** | UDP/389 from public sources (reflection probing), amplification ratio; inbound LDAP to an internal DC **that answered**; LDAP egress | T1498.002 / T1133 |
| 12 | **Bulk pull through a sealed session** | Large `bytes_toclient` on a 1–2 `tx_cnt` LDAP flow; repetition and cadence per src→dst | T1087.002 / T1018 |
| 13 | **Compare-based password guessing** | `compare_request` against `userPassword` (or another secret attribute), many `compare_false` from one source | T1110.001 |
| 14 | **JNDI / Log4Shell callback** | LDAP reply carrying `javaCodeBase`, `javaClassName`, `javaSerializedData`, `javaFactory` or `objectClass: javaNamingReference`, above all from a public server | T1190 / T1105 |
| 15 | **Cleartext directory enumeration** | Searches, entries returned and domain-root subtree searches per source on unsealed LDAP | T1087.002 / T1069.002 |

## Arguments

- `eve_path` — Path to `eve.json` (default: `eve.json` in working directory)
- `report_dir` — Case report folder (default: `report-<case>-hunt-ldap-<YYYYMMDD-HHMM>` beside `eve.json`).
  The report goes in its root; every CSV and IOC list goes in `artifacts/`. See *Output layout* below.
- `bytes` — `bytes_toclient` threshold for a bulk-pull review flag (default: `500000`)
- `spray` — distinct failing identities from one source to call it a spray, and distinct
  unknown CLDAP users to call it enumeration, and distinct sources failing for one identity
  to call it distributed brute force (default: `5`)
- `enum` — entries returned to one source over cleartext LDAP to flag it as enumeration in
  H17 (default: `1000`; a source issuing ≥ `max(200, enum/5)` searches is flagged too)

---

## Output layout — the case report folder

**Every file this routine produces goes in one case folder. Nothing is written anywhere
else, and nothing is written next to the log loose.**

```bash
eve_dir=$(cd "$(dirname "$eve")" && pwd)
case_name=$(basename "$eve" | sed 's/[-_.]\?eve.*$//; s/\.json$//')
[ -n "$case_name" ] || case_name=case
report_dir="${report_dir:-$eve_dir/report-${case_name}-hunt-ldap-$(date +%Y%m%d-%H%M)}"
mkdir -p "$report_dir/artifacts"
plugin_dir="<the hunt plugin root you loaded this SKILL.md from>"   # holds tools/mdpretty.py
skill_dir="$plugin_dir/skills/hunt-ldap"                            # holds scripts/ldap_hunt.py
```

| Path | Contents |
|---|---|
| `$report_dir/hunt-ldap-report.md` | The full written report |
| `$report_dir/README.md` | Handling warning for whoever opens this folder later — **required**, see below |
| `$report_dir/artifacts/` | **Everything else**: `bind_failures.csv`, `success_after_failures.csv`, `ntlm_binds.csv`, `unauth_ops.csv`, `anon_searches.csv`, `sensitive_attrs.csv`, `ldap_writes.csv`, `controls_by_source.csv`, `dc_inventory.csv`, `cldap_user_probes.csv`, `ldap_bind_servers.csv`, `external_ldap_flows.csv`, `top_ldap_flows.csv`, `compare_ops.csv`, `jndi_responses.csv`, `search_volume.csv`, `hunt-output.txt`, `iocs.csv`, `sha256sums.txt` |

- **Naming:** `report-<case>-hunt-ldap-<YYYYMMDD-HHMM>`. The minute-resolution timestamp
  means re-running never overwrites a previous hunt, and no previous case folder is ever
  deleted to make room.
- **Location:** beside the EVE log — never in a skills or plugin repository, and never in
  a directory you did not create for this case.
- **If the master `hunt` skill invoked this routine** it passes `report_dir` in; use it
  rather than creating a second folder. Only create one when running standalone.
- **Integrity:** finish with `cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt`.
- **Scratch is not an artifact.** The prefiltered JSONL and any ad-hoc passes go in
  `$(mktemp -d)` and are deleted — see *Clean up and housekeeping* at the end of this skill.

---

## Step 1 — Locate, size, and confirm the schema

```bash
wc -l "$eve"
grep -c '"event_type":"ldap"' "$eve"
grep '"app_proto":"ldap"' "$eve" | grep -o '"event_type":"[a-z]*"' | sort | uniq -c
grep -m1 '"event_type":"ldap"' "$eve" | jq .
```

If there are **no** `ldap` events but there are flows to 389/636/3268/3269, the LDAP
parser or its EVE logger is disabled (`app-layer.protocols.ldap`, `eve-log.types: - ldap`)
or the traffic is LDAPS. Say so — the hunt degrades to the flow-anchored sections (H12–H14).

### What Suricata logs — and, just as important, what it does not

Derived from `rust/src/ldap/logger.rs` (Suricata 8.x). Know the blind spots before you
call anything clean.

**Top level:** `timestamp`, `flow_id` (**join key**), `src_ip`/`src_port`, `dest_ip`/
`dest_port`, `proto` (`TCP` = LDAP, `UDP` = **CLDAP**), `pcap_cnt`. `app_proto` is not
emitted on `ldap` records — report `"ldap"` from the event type.

**`ldap.request`** — `message_id`, `operation`, and one of:

| Operation | Fields logged |
|---|---|
| `bind_request` | `version`, `name` (bind DN — empty for SASL and anonymous), `sasl.mechanism`, `sasl.credentials` (**hex** SPNEGO token) |
| `search_request` | `base_object`, `scope`, `deref_alias`, `size_limit`, `time_limit`, `types_only`, `filter` (**only when it is a bare `present` filter**), `attributes[]` |
| `modify_request` | `object`, `changes[].operation`, `changes[].modification.attribute_type`, `…attribute_values[]` |
| `add_request` | `entry`, `attributes[].name`, `attributes[].values[]` |
| `del_request` | `dn` |
| `mod_dn_request` | `entry`, `new_rdn`, `delete_old_rdn`, `new_superior` |
| `compare_request` | `entry`, `attribute_value_assertion.{description,value}` |
| `extended_request` | `name` (OID), `value` |
| `unbind_request` | — |
| any | `controls[].{control_type,criticality,control_value(hex)}` |

**`ldap.responses[]`** — `operation`, `message_id` (**only when the request is missing**),
and `search_result_entry.{base_object,attributes[].{type,values[]}}`,
`search_result_done` / `bind_response` / `modify_response` / `add_response` /
`del_response` / `mod_dn_response` / `compare_response` `.{result_code,matched_dn,message}`,
`bind_response.server_sasl_creds` (hex), `extended_response.{name,value}`,
`intermediate_response.{name,value}`, `controls[]`.

**Blind spots that change your conclusions:**

1. **Search filters are dropped unless they are a single `present` clause** (`(objectClass=*)`).
   Every `&`, `|`, `!`, equality or substring filter is silently omitted — including the
   ones that define Kerberoasting (`servicePrincipalName=*` inside an `&`), AS-REP roasting
   (`userAccountControl:1.2.840.113556.1.4.803:=4194304`) and BloodHound collection. **Hunt
   on the requested `attributes[]` and on response entries instead; never conclude "no
   Kerberoast query" from the absence of a filter.**
2. **Simple-bind passwords are never logged** — only the DN. A simple bind with a DN on
   389 still put the password on the wire in cleartext.
3. **SASL sign/seal blinds the parser after the bind.** Windows clients negotiate
   GSS-SPNEGO with integrity and confidentiality, so everything after the bind is wrapped
   ciphertext. Expect `anomaly` `invalid_data` / `request_not_found` on DC ports, flows with
   `tx_cnt` 1–2 and hundreds of KB, and very few post-bind searches in the log. That
   traffic is visible only through `event_type:flow` — hence H13.
4. **LDAPS (636/3269) and StartTLS are opaque.** Those flows have no `app_proto` unless TLS
   logging picked them up; count them as a visibility gap.
5. **Non-UTF-8 attribute values are escaped as literal `\xNN` text** inside the JSON string
   (e.g. the binary CLDAP `netlogon` value). Undo that before parsing — the script's
   `unescape_suricata()` does.
6. **`message_id` is not a session counter.** Windows' LDAP client numbers messages
   process-wide, so values in the hundreds of thousands are normal for a DC or a busy
   service; do not read them as "long enumeration session".

**`event_type:flow` where `app_proto` is `ldap`** — `flow.tx_cnt`, `bytes_toserver`/
`bytes_toclient`, `pkts_*`, `start`/`end`/`age`, `state`, `reason`. CLDAP flows from the
internet frequently appear **only here**, with no matching `ldap` record.

**`event_type:anomaly` with `anomaly.app_proto: ldap`** — `proto_parser` `invalid_data` and
`request_not_found` (sealed traffic, midstream pickup), `proto_detect`
`APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION`.

**`event_type:alert` on LDAP traffic** — standard alert record with `app_proto: ldap` and
the `ldap{}` object when metadata logging is on. Correlate by `flow_id`.

---

## Step 2 — Prefilter once, then run the hunt pass

`eve.json` is routinely tens of GB. One `grep` extracts every record this routine needs —
LDAP transactions, LDAP-classified flows and anomalies, and **anything to an LDAP port
whatever its classification** (LDAPS, failed detection, alerts) — into scratch. Measured:
26 s over a 20 GB log, 495 k lines out.

```bash
tmp=$(mktemp -d) || exit 1; chmod 700 "$tmp"; trap 'rm -rf "$tmp"' EXIT INT TERM
LC_ALL=C grep -E '"event_type":"ldap"|"app_proto":"ldap"|"dest_port":(389|636|3268|3269),' \
  "$eve" > "$tmp/ldap-pre.json"
wc -l < "$tmp/ldap-pre.json"

python3 -I "$skill_dir/scripts/ldap_hunt.py" "$tmp/ldap-pre.json" \
  --artifacts "$report_dir/artifacts" --bytes 500000 --spray 5 --enum 1000 \
  | tee "$report_dir/artifacts/hunt-output.txt"
```

The script is a single streaming pass (≈9 s for 495 k lines), bounded in memory, read-only
over its input. It prints sections **BASELINE**, **H1–H17** (with H6b and H7b) and writes the
CSV ledgers listed under *Output layout*. Read every section — a quiet section is a result
and goes in the report. If BASELINE prints **`WARNING: caps reached`**, some rows were
dropped to protect memory: say in the report that the view is truncated, and re-run the
affected section on a narrower prefilter (one source IP or one time window).

The script resolves hosts and DCs from the log itself: the **DC set** is every CLDAP
Netlogon responder plus every server whose rootDSE reply carries `dsServiceName`; the
**host → IP map** comes from CLDAP pings a machine sends for its own account (`User=HOST$`)
and from DC hostnames. H4 (relay), H9 (DirSync from a non-DC), H11 (rogue LDAP server) and
H13/H17 (DC sources) all depend on it. In a multi-capture corpus where lab address space
is reused, verify a hit's timestamps before calling it.

The bundled tests (`python3 -I tests/test_ldap_hunt.py`) build synthetic records for every
archetype and check the script's output and the redaction filter. Run them after editing
the script.

> The trailing `,` in the port alternation is deliberate: it stops `"dest_port":3890`
> matching `389`.

---

## Step 3 — Interpret each section

Baselines below come from a reference run over a 20 GB, multi-year corpus of
Windows-domain captures (≈287 k `ldap` events, ≈40 AD forests). Use them to tell normal
AD chatter from a finding.

### BASELINE — what normal looks like

- **Windows LDAP is almost all bind + rootDSE + CLDAP ping.** Reference mix: 55 % bind,
  37 % search, 6 % unbind; **99.99 % of SASL binds were Kerberos** (GSS-SPNEGO AP-REQ),
  NTLM was 9 binds out of 158 k.
- **The rootDSE query** (`base_object:""`, `filter: present objectclass`, 15 attributes
  ending `supportedCapabilities`) and the **CLDAP Netlogon ping** (UDP/389,
  `attributes:["Netlogon"]`, no logged filter) are the DC locator. They are benign in any
  volume and should not be reported as recon.
- **DC-to-DC LDAP is heavy.** A DC as both top client and top server is replication and
  referral traffic, not lateral movement.

### H1–H3 — Bind mechanisms, cleartext and anonymous binds

- `simple:named` — **any** count is a finding on 389: the password crossed the wire in
  cleartext. Name the DN (service accounts are the usual culprits) and recommend LDAPS or
  SASL.
- `simple:anonymous` followed by searches — see H6. A Windows client that binds with
  Kerberos and then re-binds anonymously on the same connection (reference: two hosts,
  six binds) is unusual; check H11 for that host's machine account.
- `sasl:…:ntlm-auth` in a Kerberos-dominated domain is the thread to pull — go to H4.

### H4 — NTLM-over-LDAP identities and relay indicators

The script decodes each NTLMSSP `AUTHENTICATE` to `domain\user@workstation`, the NTLM
version and the `NEGOTIATE_SIGN` bit, and joins the bind result.

**How relay looks on the wire.** In a relay (ntlmrelayx after PetitPotam, PrinterBug or
DFSCoerce) the attacker forwards the victim's `AUTHENTICATE` message **unchanged**, so the
workstation field still names the victim: `DC01$` from workstation `DC01`. A matching
user and workstation therefore proves nothing. What gives the relay away is the **source
IP**: the message reaches the DC from the attacker's host, not from DC01. Flags:

| Flag | Meaning |
|---|---|
| `RELAY: machine acct X$ bound from IP but x is seen at …` | **Strong relay indicator.** Host X's own account authenticates from an address that is not X (X's addresses come from its own CLDAP pings and the DC inventory). With `[DC ACCOUNT — coerced DC auth relayed]` it is a DC's account: coerced authentication relayed to LDAP, the precursor to RBCD, shadow-credential or DACL writes. Go straight to H8 and H9 for the same source. |
| `RELAY: DC machine acct X$ bound from non-DC IP` | Same, when only the DC name (not its IP) is known. |
| `machine-account NTLM without SIGN (relay with --remove-mic?)` | Windows sets `NEGOTIATE_SIGN` for its own account. A cross-protocol relay (SMB → LDAP) has to strip it (`--remove-mic`). |
| `workstation field W != account` | Message built by a tool rather than Windows (impacket with a hard-coded or empty workstation, or a forged name). Weaker than the IP mismatch. |
| `unsigned successful bind (relayable)` | NTLM bind succeeded without `NEGOTIATE_SIGN`; the DC does not enforce LDAP signing. Finding on its own, critical next to a relay. |
| `NTLMv1` | 24-byte NT response — downgrade; offline-crackable to the NT hash. |
| `identity seen from N src IPs` | Same account binding from several hosts — relay, credential reuse or a roaming service account; check against asset data. |

The IP check is only as good as the host → IP map. When a host never sent a CLDAP ping
in the capture, nothing is flagged for its account. Fall back on `identity seen from N
src IPs` and on the DHCP, Kerberos and SMB pivots in Step 4.

**Reference example — benign-but-broken:** `swutrust\WKPAJ8D43S$` from workstation
`WKPAJ8D43S`, NTLMv2, signed, `invalid_credentials` seven times. Consistent with a stale
machine password (broken secure channel): the binds are signed and every one failed. Before
calling it benign, confirm the source IP belongs to WKPAJ8D43S. The matching workstation
name alone does not rule out relay.

### H5 — Bind failures, spray and brute force

AD puts the real reason in `message` as `data XXX`:

| `data` | Meaning | | `data` | Meaning |
|---|---|---|---|---|
| `525` | user not found | | `532` | password expired |
| `52e` | bad password | | `533` | account disabled |
| `530` | logon-hours restriction | | `701` | account expired |
| `531` | workstation restriction | | `773` | must reset password |
| `775` | **account locked out** | | | |

- **Spray** — `distinct ≥ --spray` identities failing from one source. A `525` mix means
  the attacker is guessing usernames too.
- **Brute force** — one identity, many attempts, short interval.
- **Cadence** — the script prints the most common `mm:ss` per identity. **Failures at the
  same minute and second every N hours are a scheduled task with stale credentials**
  (reference: `:52:03`, every 2 h, machine account) — hygiene, not attack.
- **A single user failing once or twice is low on its own — unless the host has other
  findings.** Always run Step 4 on every source in this section.
- **Success after failures** — the script lists every NTLM or simple bind that **succeeded**
  from a source after that source's first failure. `SPRAY->SUCCESS` (the source also
  sprayed) and `BRUTE->SUCCESS` (the same identity failed earlier) mean the attacker
  **found a working password**: that account is compromised until proven otherwise. Hunt
  its later activity before anything else. A plain `success after failures` is often a user
  mistyping and then getting it right; weigh it by Step 4. Kerberos successes carry no
  identity in LDAP and are not listed. Check `krb5` for the same host.
- **One identity failing from many sources** (`≥ --spray` sources) — distributed brute force
  against one account, or a credential being tested across hosts. Exclude a service
  account with a stale password deployed on many servers (same `mm:ss` cadence everywhere).

**Reference example — the real incident in the corpus:** `FANGTOOTH\joel.henderson` from
`DESKTOP-JKG8ET2` (`172.17.2.65`) failed two NTLM binds 1.5 s apart. Step 4 put them
minutes after the host opened TLS to `callbackhubs.com` with an OpenSSL-default
certificate (alerted), resolved `policyupdating.com` and pulled files over HTTP from its IP,
and opened SMB1 sessions to the DC on port 139; ten seconds after the last bind, an
`ET MALWARE Cobalt Strike Malleable C2 Profile` alert fired on that HTTP channel.
Post-infection AD discovery using the victim's credentials — and two quiet LDAP failures
were the only LDAP-visible edge of a Cobalt Strike compromise.

### H6 — Unauthenticated operations (`000004DC`)

`operations_error` with `000004DC … a successful bind must be completed` = a search sent
on an anonymous connection. Attackers use it to test null-session reads. **Context
matters:** in the reference set the only hits were a host reading its *own* computer
object (`userCertificate`, `allowedAttributesEffective`, `<SID=…>` lookups) after its
machine account went missing (H11 opcode 25 for the same host) — a broken domain member,
not an attacker. A host reading *other* objects, or `namingContexts` enumeration beyond
rootDSE, is the hostile version.

### H6b — Searches on anonymous-bound connections

H6 only sees searches the DC **refused**. When a DC allows anonymous reads (`dsHeuristics`
7th character = `2`, or an OpenLDAP default), the null-session dump succeeds and produces
no `000004DC` at all. H6b follows every flow that completed an explicit anonymous bind and
lists the non-rootDSE searches on it, with the entries returned. **`ENTRIES RETURNED
ANONYMOUSLY` is a finding:** the directory is readable without credentials. Name the DC and
recommend disabling anonymous access. A connection that searches without sending any bind
is also anonymous, but cannot be told apart from a capture that started after the bind,
so it is not flagged.

### H7 / H7b — Sensitive attributes requested and returned

Category tags from the script's `SENSITIVE_ATTRS` map:

| Tag | Attributes | Why it matters |
|---|---|---|
| `secret:LAPS` / `secret:LAPS-DSRM` / `secret:gMSA` / `secret:password` | `ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword[History]`, `msLAPS-EncryptedDSRMPassword[History]`, `msDS-ManagedPassword`, `unicodePwd`, `userPassword`, `unixUserPassword`, `msSFU30Password`, `supplementalCredentials` | Credential theft. **H7b hit = the secret crossed the wire in cleartext.** |
| `secret:BitLocker` / `secret:TPM` | `msFVE-RecoveryPassword`, `msTPM-OwnerInformation` | Disk-encryption recovery keys — offline access to stolen laptops |
| `secret:trust` | `trustAuthIncoming`, `trustAuthOutgoing` | Inter-forest trust keys — forged inter-realm tickets |
| `shadow-credentials` | `msDS-KeyCredentialLink` | Read = recon for Whisker/pyWhisker; write = H8 |
| `kerberoast` / `asrep/uac` | `servicePrincipalName`, `msDS-SupportedEncryptionTypes`, `userAccountControl` | Roast target selection (filter is not logged — the attribute list is your evidence) |
| `rbcd` / `delegation` | `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-AllowedToDelegateTo` | Delegation abuse recon |
| `acl` / `acl-probe` | `nTSecurityDescriptor`, `allowedAttributesEffective` | BloodHound ACL collection; "what can I write?" probing |
| `adcs` | `pKIExtendedKeyUsage`, `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `msPKI-Certificate-Application-Policy`, `cACertificate` | Certipy/Certify ESC enumeration |
| `cert-mapping (ESC14)` | `altSecurityIdentities` | Explicit certificate mapping — read = recon, write = H8 |
| `maq` | `ms-DS-MachineAccountQuota`, `mS-DS-CreatorSID` | MachineAccountQuota abuse recon; who created which computer |
| `all-attributes` | `*` / `+` in the attribute list | Bulk dump tooling |

Rank by **who** asks: a workstation requesting `nTSecurityDescriptor` + `servicePrincipalName`
+ `msDS-AllowedToActOnBehalfOfOtherIdentity` across a whole naming context is
SharpHound-shaped; a management server reading LAPS for its helpdesk app may be normal.
The script prints the category set per source and marks **`BLOODHOUND-SHAPED`** when one
source covers `acl` + `kerberoast` + (`rbcd` or `delegation`).

### H8 — Directory writes

Rare on the wire from workstations (most admin writes ride sealed sessions), so **any
cleartext-visible write is worth a line in the report.** Flags:

| Flag | Technique |
|---|---|
| `shadow-credentials` on a computer or DC object | Shadow Credentials → PKINIT as that account (T1098) |
| `rbcd` | Resource-based constrained delegation takeover |
| `kerberoast` (SPN write) | Targeted Kerberoast |
| `machine-account-add` | MachineAccountQuota abuse (noPac, RBCD staging). Detected from `objectClass: computer` or a `sAMAccountName` ending `$`, so a computer created in **any** OU is caught, not only `CN=Computers` |
| `NOPAC: sAMAccountName set to a DC name without $` / `noPac? …` | CVE-2021-42278/42287: a computer account renamed to the DC's name without `$`, then a TGT requested and the name restored. The DC-name variant is critical |
| `upn-change (ESC9/ESC10?)` | `userPrincipalName` set on an account you control to impersonate another in certificate mapping |
| `cert-mapping (ESC14)` | `altSecurityIdentities` write — explicit certificate mapping, persistence |
| `DACL WRITE ON DOMAIN ROOT (DCSync-rights grant?)` | `nTSecurityDescriptor` modified on the `DC=…` head: granting replication rights (ntlmrelayx `--escalate-user`, WriteDacl abuse). Critical |
| `DACL WRITE ON AdminSDHolder` / `DACL write on GPO` | ACL persistence on protected accounts / GPO takeover |
| `primaryGroupID-change` | Hidden membership in a privileged group (e.g. 512) |
| `group-membership` / `PRIVILEGED-GROUP` | `member` change; `PRIVILEGED-GROUP` when the target's first RDN is Domain/Enterprise/Schema Admins, Administrators, Account/Backup/Server/Print Operators, DnsAdmins, Group Policy Creator Owners, (Enterprise) Key Admins, Cert Publishers, (Enterprise) Domain Controllers or the Exchange permission groups. Matched on English names: renamed or localised groups need a manual look at every `group-membership` row |
| `gpo` / `gpo-extension` / `logon-script` | `gPCFileSysPath`, `gPLink`, `gPC{Machine,User}ExtensionNames` (SharpGPOAbuse adds a scheduled-task CSE), `scriptPath` — persistence |
| `certifried?` | `dNSHostName` write (CVE-2022-26923) — reported only for writes |
| `TREE-DELETE (recursive)` / `delete` | `del_request`, with the tree-delete control = a whole subtree removed |

Report the `result` column: an `insufficient_access_rights` write is a **failed attempt**,
still a finding.

### H9 — Controls and extended operations

Controls are listed **per source → destination** (`controls_by_source.csv`), and the
script raises these flags per source:

- **DirSync** `1.2.840.113556.1.4.841` or **DirSync_EX** `…4.2090` from a source that is not
  a known DC — secret replication over LDAP. Treat like DCSync. Allow-list Entra Connect /
  other sync servers by name before reporting.
- **SD_FLAGS** `…4.801` + **paged results** `…4.319` from the same source —
  security-descriptor bulk collection (BloodHound).
- **TREE-DELETE** `…4.805` — recursive deletion of a subtree: destructive.
- **ASQ** `…4.1504` — attribute-scoped query, walking group membership in one request.
- **show-deleted / show-recycled** — tombstone mining.
- **`PasswordModify`** (`1.3.6.1.4.1.4203.1.11.1`) — a password change over LDAP. Its
  request `value` holds the new password in cleartext BER; the script never records it, and
  `redact.jq` blanks it in excerpts. Name the target from the bind identity on the flow.
- **`StartTLS`** — the remainder of that flow is encrypted; note it as a visibility gap,
  not a finding.

### H10 — rootDSE fingerprints

Groups rootDSE queries by `(time_limit, size_limit, filter, n_attrs, attrs)`. Windows'
locator sends 15 attributes with `time_limit` 120 (reference: 58 k queries, 294 clients);
other Windows components use 30/60/180/300. **A fingerprint seen from ≤ 3 clients with a
different attribute set** — `*`, `+`, `namingContexts` alone — is non-Windows tooling
(ldapsearch, nmap `ldap-rootdse`, impacket, ldapdomaindump). Confirm before calling it: in
the reference set the only rare fingerprint was two DCs.

### H11 — CLDAP Netlogon: DC inventory, rogue responders, user enumeration

The script decodes the binary `netlogon` value (MS-ADTS `NETLOGON_SAM_LOGON_RESPONSE_EX`):
responder IP → DNS domain, DC hostname, NetBIOS domain, DC site. `dc_inventory.csv` is the
authoritative list of domain controllers seen on the wire.

- **One DC hostname answering from > 1 IP** — rogue DC, a responder, or simply
  re-addressing. In a single-site capture it is suspicious; in a multi-capture corpus
  (reference: lab domains reused across years) it is expected. Check timestamps.
- **Opcode 25 `USER_UNKNOWN_EX`** — the DC does not know the user in the ping. A single
  machine account (`HOST$`) from its own host = broken or deleted computer account
  (reference: `WORKD89RQ$`, `DESKTOP-YRZ2RFD$`) — hygiene.
- **CLDAP user enumeration** — CLDAP ping enumerators send
  `(User=<name>)` for each candidate. The DC answers opcode **23 with the user name echoed**
  when the account exists and opcode **25** when it does not, without logging a failed
  logon. The script counts distinct users per source across both, leaving out the
  source's own machine account, and flags `≥ --spray` as `ENUMERATION: … N VALID [...]`.
  **The VALID list is the attacker's harvested username list**: expect those accounts in a
  spray (H5) or AS-REP roast (`krb5`) next. `cldap_user_probes.csv` holds every probe.
- **TCP LDAP binds to a host that is not a known DC** — a Responder / ntlmrelayx LDAP
  listener collecting credentials, a misconfigured application pointing at the wrong
  server, or a legitimate non-AD directory (OpenLDAP, an appliance). `ldap_bind_servers.csv`
  lists every bind target with its mechanisms. A non-DC server receiving NTLM or simple
  binds from many clients, or any public one, is the finding. Without CLDAP or rootDSE
  data in the log there is no DC set, and the script says so instead of guessing.

### H12 — Internet LDAP / CLDAP (flow-anchored)

Classifies every LDAP flow with a public endpoint:

- **`internet-to-internet` UDP/389** — the sensor sees internet-facing hosts being probed
  for **CLDAP reflection/amplification**. The script computes per-destination
  `bytes_back / bytes_out`. An open AD CLDAP responder answers a ~60-byte probe with
  ~3 KB (amp ≫ 10×); reference: 1 104 flows from 417 sources against three hosts, amp
  ≈ 1.3× or no reply — **probed, not exploitable**. Still report the scanning and the
  exposure. Destinations above 10× are tagged `OPEN REFLECTOR`.
- **`inbound-from-internet`** to an internal DC with replies — **directory exposed to the
  internet**. Critical. Each category prints `answered=N` (flows with server packets); the
  script tags `INBOUND ANSWERED` when any inbound flow got a reply.
- **`outbound-to-internet`** — a domain member speaking LDAP/CLDAP to a public IP:
  misconfigured VPN/DC locator, or a rogue LDAP server (JNDI/Log4Shell callback,
  credential capture). Investigate the destination, and read H16 for the same client.

"Internet" means a globally routable address (`ipaddress.is_global`). CGNAT
(100.64.0.0/10) and the documentation ranges count as internal; in a carrier or VPN
network where CGNAT space is genuinely external, re-check those flows by hand.

### H13 — Volume: bulk pulls through sealed sessions

Ranks LDAP flows by `bytes_toclient` and aggregates flows ≥ `--bytes` per src→dst with the
**median gap** between them.

- A one-off flow of several MB from a workstation to a DC = **directory dump**
  (SharpHound, ADExplorer, ldapdomaindump) even though the content is sealed. Pivot to
  Step 4 for that host and time.
- **Repeated pulls every 90–120 min are Group Policy background refresh** (90 min + 0–30
  min random offset) — the script tags this. Reference: two hosts, 144 flows of ~650 KB,
  median gap 102–107 min — benign. A fixed interval *without* jitter, or off-hours-only
  pulls, is not GPO.
- Single large flows per src→dst are tagged `ONE-OFF PULL`, and large flows whose source is
  a known DC are marked `(src is a DC)` (replication, usually benign).

### H14 — Visibility gaps

Quantify, then state them in the report:

- `invalid_data` / `request_not_found` anomalies per DC — sealed SASL traffic (reference:
  8 k anomalies, 7 k on one DC). Expected, not hostile.
- LDAP-port flows **not** classified `ldap` — 636/3269 (LDAPS) are opaque; 389 with no
  `app_proto` is usually midstream pickup or a torn-down handshake. Each row is marked
  `internal` or `EXTERNAL`. External LDAPS is invisible egress or exposure, and the
  `ldaps://` form of a JNDI callback lands here rather than in H16.

### H15 — Compare operations

`compare_request` asks the server "does attribute A of entry E equal V?" and gets
`compare_true` / `compare_false`. Against `userPassword` (OpenLDAP and other non-AD
directories that store it comparably) it is a **password-guessing oracle** that, depending
on the server's password policy, may not count towards bind lockout or appear in
failed-logon logs. The script lists every compare with its attribute
and result, never the asserted value, and flags `PASSWORD COMPARE` per source; `≥ --spray`
compares is tagged `BRUTE FORCE`. Compares on non-secret attributes are usually
application logic (group-membership checks); report them only next to other findings.

### H16 — JNDI / Log4Shell references in LDAP responses

A Log4Shell (`${jndi:ldap://…}`) or other JNDI-injection victim connects out to the
attacker's LDAP server, which answers with a Java reference: `javaClassName`,
`javaCodeBase` (the URL to fetch the class from), `javaFactory`, `javaSerializedData`
(a serialised gadget chain) or `objectClass: javaNamingReference`. **Any such reply from a
public server is a confirmed exploitation attempt that reached the vulnerable host**, and
`javaCodeBase` names the next-stage download. Pivot at once (Step 4) for HTTP to that URL and
for C2 from the client. Callbacks commonly use non-standard ports (1389, 1099, …).
Suricata's LDAP probe still classifies them, and the prefilter's `"app_proto":"ldap"`
catches them. Internal servers returning these attributes can be legitimate Java
applications storing objects in LDAP; check before calling it. Serialised values are never
printed, only counted.

### H17 — Cleartext search volume per source

H7 only fires on specific attributes. A dump that asks for ordinary ones (`member`,
`sAMAccountName`, `description`) goes unnoticed there. H17 counts per source, over
unsealed TCP LDAP: searches (rootDSE excluded), entries returned, subtree searches at a
`DC=…` domain root, and distinct search bases. A source returning ≥ `--enum` entries, or
issuing ≥ `max(200, enum/5)` searches, is tagged `ENUMERATION` (ldapdomaindump,
windapsearch, adidnsdump, BloodHound.py without sealing). DCs, sync servers and
management tools are expected high; the tag shows `(src is a DC)`. On a Windows network
most of this traffic is sealed and H17 is quiet: then H13 is the volume signal.

### Alerts and other result codes

- **No signature fired** is the normal outcome — say so; the hunt is behavioural. The
  rules under *Closing the detection gap* cover most archetypes.
- `strong_auth_required`, `confidentiality_required` — the DC refused an unsigned or
  cleartext operation (LDAP signing enforced). Good news about the DC, bad news about the
  client that tried.
- `insufficient_access_rights` on a write — a failed privilege attempt; report it.

---

## Step 4 — Cross-protocol pivot for every flagged host

LDAP is rarely the first thing an intruder touches. For each source in H2, H4 (flagged),
H5 (including success-after-failures and distributed), H6 (non-self), H6b, H7, H8, H9
(flagged), H11 (enumeration, and clients of a non-DC bind target), H13 (one-off pulls),
H15, H16 (the client) and H17 (flagged), pull **all** event types for that IP in a window
around the LDAP activity:

```bash
ip="172.17.2.65"; win="2022-05-11T00:4"        # IP and timestamp prefix for the window
LC_ALL=C grep -F "\"$ip\"" "$eve" | LC_ALL=C grep -F "\"timestamp\":\"$win" > "$tmp/pivot.json"
jq -r '[.timestamp[11:23], .event_type, .src_ip, .dest_ip, (.dest_port|tostring),
        (.app_proto//""),
        (.alert.signature // .dns.queries[0].rrname // .dns.rrname // .tls.sni //
         .http.hostname // .smb.command // .krb5.cname // .ldap.request.operation // "")]
       | @tsv' "$tmp/pivot.json" | sort | head -120
```

Read it as a timeline: **initial access → C2 → AD discovery → credential use → write**.
Hand off when it leaves LDAP — SMB/DCERPC to `@hunt-smb-dcerpc`, TLS C2 to `@hunt-tls-c2`,
DNS anomalies to `@hunt-dns-tunnel` — and tell the user you are doing so.

Also join the CLDAP inventory to the rest of the hunt: every IP in `dc_inventory.csv` is a
DC, which turns SMB/DCERPC targets and Kerberos servers elsewhere in the log into named
domain controllers.

---

## Step 5 — Pull evidence rows for the report

For each headline finding take the `flow_id` from the CSV and dump the record:

```bash
fid=1179469743384035
grep -F "\"flow_id\":$fid," "$eve" | grep '"event_type":"ldap"' | head -3 \
  | jq -c -f "$skill_dir/scripts/redact.jq"
grep -F "\"flow_id\":$fid," "$eve" | grep '"event_type":"flow"' | jq -c .
```

**Pipe every `ldap` excerpt through `scripts/redact.jq`**, whatever the operation, and show
the `-f …/redact.jq` in the command line printed above the excerpt. It truncates bind
tokens (`sasl.credentials`, `server_sasl_creds`) to 32 hex characters and replaces with
`…[redacted — secret value]` the PasswordModify request value, compare assertions against
secret attributes, the values of secret attributes in modify/add requests and the values of
secret attributes returned in search entries. Every rewrite is guarded with
`if … then … else . end`, so records without those fields pass through byte-identical
and the excerpt stays verbatim. Do not hand-write a narrower `jq` filter in its place.
Capture:
`timestamp`, `flow_id`, `proto` (TCP/UDP), `src→dst:port`, operation, identity or DN,
result code + AD `data` sub-code, flow bytes/`tx_cnt`/age, and the H-section that flagged it.

Write `artifacts/iocs.csv` with one row per indicator (`type,value,role,first_seen,last_seen,source_section`)
— internal hosts, attacker IPs, account names, DNs written to.

---

## Step 6 — Print & save the report

Print to the terminal AND write to `$report_dir/hunt-ldap-report.md`. Do **not** truncate
DNs, account names, attribute names or OIDs — they are the evidence. (The `credentials`
blob is the one field that is always truncated.)

```
╔══════════════════════════════════════════════════════════════════════════╗
║   LDAP / CLDAP HUNT REPORT — eve.json                                     ║
╠══════════════════════════════════════════════════════════════════════════╣
║  File   : /path/to/eve.json                                               ║
║  Scope  : event_type:ldap + flow/anomaly/alert on 389/636/3268/3269       ║
║  Volume : N ldap events | N ldap flows | N CLDAP | window first → last    ║
╠══════════════════════════════════════════════════════════════════════════╣
║  VERDICT: [CONFIRMED / SUSPICIOUS / CLEAN] — [techniques]                 ║
╚══════════════════════════════════════════════════════════════════════════╝

── BASELINE ────────────────────────────────────────────────────────────────
  op mix | bind mechanisms (Kerberos / NTLM / simple / anonymous) | result codes
  domains & DCs (from CLDAP inventory)

── FINDING 1..N (one per archetype hit) ────────────────────────────────────
  hosts, identity, DN/attributes, result, count, window, cross-protocol context

── EVIDENCE TABLE ──────────────────────────────────────────────────────────
| # | proto | src → dest:port | flow_id | operation | identity / DN | result (data) | section |

── ASSESSED BENIGN ─────────────────────────────────────────────────────────
  GPO refresh pulls, stale machine passwords, broken computer accounts, DC locator …

── VISIBILITY GAPS ─────────────────────────────────────────────────────────
  sealed-session anomalies, LDAPS/3269 flows, unlogged filters

── INDICATOR CHECKLIST ─────────────────────────────────────────────────────
  [PASS/FAIL/INFO]  indicator  →  observed value

── OUTPUT ──────────────────────────────────────────────────────────────────
  <report_dir>/
    hunt-ldap-report.md, README.md
    artifacts/  *.csv, hunt-output.txt, iocs.csv, sha256sums.txt
```

Supporting files are already in `$report_dir/artifacts/`; hash them:

```bash
cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt
```

### Always print a summary table to the terminal as well

The report file is the record; the terminal table is what the reader actually sees.
**Print both, every run** — writing the file is not delivery.

```bash
printf '| %-24s | %-49s |\n' "Item" "Value"
printf '|%s|%s|\n' "$(printf '%.0s-' {1..26})" "$(printf '%.0s-' {1..51})"
printf '| %-24s | %-49s |\n' \
  "Verdict"           "<CONFIRMED|SUSPECTED|CLEAN> — <technique>" \
  "Affected host(s)"  "<internal IPs / hostnames>" \
  "Accounts involved" "<domain\\user — sensitive, terminal only>" \
  "Domain controllers" "<from CLDAP inventory>" \
  "Headline volume"   "<binds, failures, writes, bytes>" \
  "Window / rate"     "<first -> last>" \
  "Suricata alerts"   "<n on LDAP traffic>" \
  "Visibility gaps"   "<sealed/LDAPS flows>" \
  "Report"            "hunt-ldap-report.md" \
  "Artifacts"         "<n> files in artifacts/"
```

Every value in the table must already appear in the report file.

---

## Closing the detection gap — Suricata rules

When the hunt found activity no signature caught, offer these. All load cleanly on
Suricata 8.0.4 and 9.0.0-dev (`suricata -T -S ldap-hunt.rules`: 18 loaded, 0 failed); that
is a syntax check, not a test against traffic. SIDs are in a local range —
renumber for the site. Note that `ldap.request.attribute_type` covers search attributes,
modify `attribute_type`, add attribute names and compare descriptions.

```
alert ldap any any -> any any (msg:"LDAP bind failures - invalid credentials burst"; flow:established,to_client; ldap.responses.operation:bind_response; ldap.responses.result_code:invalid_credentials,any; threshold:type both,track by_dst,count 5,seconds 60; classtype:attempted-user; sid:9900001; rev:1;)
alert ldap any any -> any any (msg:"LDAP bind failed - account locked out (AD data 775)"; flow:established,to_client; ldap.responses.message; content:"data 775"; classtype:attempted-user; sid:9900002; rev:1;)
alert ldap any any -> any any (msg:"LDAP operation attempted without bind (000004DC)"; flow:to_client; ldap.responses.message; content:"000004DC"; classtype:attempted-recon; sid:9900003; rev:1;)
alert ldap any any -> any any (msg:"LDAP bind with non-empty DN - likely simple bind, cleartext password"; flow:established,to_server; ldap.request.operation:bind_request; ldap.request.dn; bsize:>0; classtype:policy-violation; sid:9900004; rev:1;)
alert ldap any any -> any any (msg:"LDAP search requests LAPS password attribute"; flow:to_server; ldap.request.operation:search_request; ldap.request.attribute_type; content:"ms-mcs-admpwd"; nocase; classtype:attempted-recon; sid:9900005; rev:1;)
alert ldap any any -> any any (msg:"LDAP search requests gMSA managed password"; flow:to_server; ldap.request.operation:search_request; ldap.request.attribute_type; content:"msds-managedpassword"; nocase; classtype:attempted-recon; sid:9900006; rev:1;)
alert ldap any any -> any any (msg:"LDAP response returns LAPS password in cleartext"; flow:to_client; ldap.responses.attribute_type; content:"ms-mcs-admpwd"; nocase; classtype:policy-violation; sid:9900007; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify - shadow credentials msDS-KeyCredentialLink"; flow:to_server; ldap.request.operation:modify_request; ldap.request.attribute_type; content:"msds-keycredentiallink"; nocase; classtype:attempted-admin; sid:9900008; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify - RBCD msDS-AllowedToActOnBehalfOfOtherIdentity"; flow:to_server; ldap.request.operation:modify_request; ldap.request.attribute_type; content:"msds-allowedtoactonbehalfofotheridentity"; nocase; classtype:attempted-admin; sid:9900009; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify - servicePrincipalName write (targeted kerberoast)"; flow:to_server; ldap.request.operation:modify_request; ldap.request.attribute_type; content:"serviceprincipalname"; nocase; classtype:attempted-admin; sid:9900010; rev:1;)
alert ldap any any -> any any (msg:"LDAP add - new computer object (MachineAccountQuota abuse)"; flow:to_server; ldap.request.operation:add_request; ldap.request.dn; content:"CN=Computers,"; nocase; classtype:attempted-admin; sid:9900011; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify of privileged group membership"; flow:to_server; ldap.request.operation:modify_request; ldap.request.dn; pcre:"/^CN=(Domain Admins|Enterprise Admins|Administrators|Schema Admins|Account Operators|Backup Operators|DnsAdmins),/i"; classtype:attempted-admin; sid:9900012; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify - sAMAccountName rename (noPac CVE-2021-42278 staging)"; flow:to_server; ldap.request.operation:modify_request; ldap.request.attribute_type; content:"samaccountname"; nocase; bsize:14; classtype:attempted-admin; sid:9900013; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify - userPrincipalName or altSecurityIdentities write (ADCS ESC9/ESC10/ESC14)"; flow:to_server; ldap.request.operation:modify_request; ldap.request.attribute_type; pcre:"/^(userprincipalname|altsecurityidentities)$/i"; classtype:attempted-admin; sid:9900014; rev:1;)
alert ldap any any -> any any (msg:"LDAP modify - nTSecurityDescriptor on domain root (DCSync rights grant)"; flow:to_server; ldap.request.operation:modify_request; ldap.request.dn; pcre:"/^DC=[^,]+(,DC=[^,]+)*$/i"; ldap.request.attribute_type; content:"ntsecuritydescriptor"; nocase; classtype:attempted-admin; sid:9900015; rev:1;)
alert ldap any any -> any any (msg:"LDAP compare against userPassword (password guessing oracle)"; flow:to_server; ldap.request.operation:compare_request; ldap.request.attribute_type; content:"userpassword"; nocase; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-user; sid:9900016; rev:1;)
alert ldap any any -> any any (msg:"LDAP search requests BitLocker recovery password"; flow:to_server; ldap.request.operation:search_request; ldap.request.attribute_type; content:"msfve-recoverypassword"; nocase; classtype:attempted-recon; sid:9900017; rev:1;)
alert ldap any any -> any any (msg:"LDAP response carries JNDI Java reference (Log4Shell-style callback)"; flow:to_client; ldap.responses.attribute_type; pcre:"/^java(codebase|serializeddata|factory|classname)$/i"; classtype:trojan-activity; sid:9900018; rev:1;)
```

Rule 9900004 also fires on SASL binds that carry a DN — rare against AD, common against
OpenLDAP; scope it with `$HOME_NET`/DC address groups. Rule 9900011 only sees computers
added under `CN=Computers` (the attribute values that reveal `objectClass: computer` have
no rule buffer); the hunt's H8 has no such limit. Rules 9900013/9900014 also fire on
legitimate renames and UPN changes made over unsealed LDAP; scope them to non-admin
sources. Rule 9900018 is the one to deploy widely: legitimate JNDI references from the
internet do not exist. NTLM relay (it needs the host → IP map), success after spray, CLDAP
enumeration, DirSync from a non-DC (no control keyword) and sealed bulk pulls have no
practical signature — they stay hunt-only.

---

## Indicator checklist — malicious LDAP / CLDAP

| Indicator | Archetype | How to detect |
|---|---|---|
| ≥ N distinct identities failing `invalid_credentials` from one source | Spray | H5 `distinct` |
| Successful bind from a source after its failures (`SPRAY->SUCCESS` / `BRUTE->SUCCESS`) | **Spray / brute force succeeded** | H5 success-after-failures |
| One identity failing from ≥ N sources | Distributed brute force / credential testing | H5 many-sources |
| AD `data 775` in a bind failure | Spray fallout | H5 `ad_data` |
| AD `data 525` mixed with `52e` | Username guessing | H5 |
| Identical `mm:ss` failure cadence | Stale creds (benign) | H5 cadence |
| NTLM machine account `X$` from an IP that is not host X (esp. a DC account) | NTLM relay | H4 `RELAY:` |
| Machine-account NTLM without `NEGOTIATE_SIGN` | Cross-protocol relay (`--remove-mic`) | H4 |
| NTLM workstation field ≠ machine account name | Tool-built message | H4 |
| Successful NTLM bind without `NEGOTIATE_SIGN` | Relayable DC | H4 |
| NTLMv1 (24-byte NT response) | Downgrade | H4 |
| Same NTLM identity from > 1 source IP | Relay / reuse | H4 |
| `simple:named` bind on 389 | Cleartext password | H1–H2 |
| Anonymous bind followed by searches that return entries | Null-session dump; DC allows anonymous reads | H3, H6b |
| `000004DC` on objects other than the requester's own | Unauth recon | H6 |
| `compare_request` against `userPassword` / secret attribute | Password-guessing oracle | H15 |
| LAPS / gMSA / BitLocker / trust-key / password attribute requested | Credential access | H7 |
| Secret attribute present in a response | Cleartext secret exposure | H7b |
| `acl` + `kerberoast` + `rbcd`/`delegation` categories from one workstation | BloodHound | H7 `BLOODHOUND-SHAPED` |
| ≥ `--enum` entries or many searches to one source over cleartext LDAP | Directory enumeration | H17 |
| Write to `msDS-KeyCredentialLink` / RBCD / SPN | Shadow creds / RBCD / roast | H8 |
| `sAMAccountName` write without `$` (esp. to a DC name) | noPac | H8 |
| `userPrincipalName` / `altSecurityIdentities` write | ADCS ESC9 / ESC10 / ESC14 | H8 |
| `nTSecurityDescriptor` write on the domain root or AdminSDHolder | DCSync-rights grant / ACL persistence | H8 |
| `add_request` creating a computer object (any OU) | MAQ abuse | H8 |
| Modify on a privileged group DN, or `primaryGroupID` change | Privilege escalation | H8 |
| `gPC*ExtensionNames` / `gPCFileSysPath` / `scriptPath` write | GPO / logon-script persistence | H8 |
| DirSync or DirSync_EX from a non-DC source | Secret replication (DCSync over LDAP) | H9 flags |
| SD_FLAGS + paged results from one source | ACL bulk dump | H9 flags |
| Tree-delete control | Destructive deletion | H9, H8 |
| Rare rootDSE fingerprint | Non-Windows tooling | H10 |
| ≥ N users probed by CLDAP from one source (valid ones listed) | CLDAP user enum | H11 `ENUMERATION` |
| One DC hostname from > 1 IP in a single capture | Rogue DC | H11 |
| TCP LDAP binds to a host that is not a known DC | Rogue LDAP server / credential capture | H11 |
| JNDI attributes (`javaCodeBase`, `javaSerializedData` …) in an LDAP reply | Log4Shell / JNDI exploitation | H16 |
| UDP/389 from internet with amp ≫ 10× | Open CLDAP reflector | H12 `OPEN REFLECTOR` |
| Inbound LDAP from internet to a DC with replies | Exposed directory | H12 `INBOUND ANSWERED` |
| External LDAPS / LDAP-port flows not classified `ldap` | Opaque egress / exposure | H14 `EXTERNAL` |
| One-off multi-MB `bytes_toclient` LDAP flow from a workstation | Directory dump | H13 `ONE-OFF PULL` |
| 90–120 min jittered pulls | GPO refresh (benign) | H13 |
| `WARNING: caps reached` in BASELINE | Truncated view — re-run narrower | BASELINE |
| No Suricata signature on any of the above | Detection gap | Alerts section |


### Pretty-print the report to the terminal

Raw Markdown in a terminal is not a delivery. Render the report with the bundled printer
(no Markdown viewer required):

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-ldap-report.md"
```

Colour is automatic — ANSI on a TTY, plain text when redirected, so `> out.txt` never
captures escape codes. Width follows `$COLUMNS` (cap 118); `--width N` and `--no-color`
override. Tables too wide for a grid become one labelled block per row, which is what
keeps DNs and OIDs untruncated as this routine requires.



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

**Start here:** `hunt-ldap-report.md` — the full findings, including whatever was assessed as benign.
Supporting evidence is in `artifacts/`, with `artifacts/sha256sums.txt` fixing its integrity.
This folder names directory accounts and domain controllers; treat it as an inventory of the Active Directory.
```

Keep the wording above and keep it generic. Adjust only the "Start here" line to name this
hunt's report file, and add at most one sentence naming the specific hazard when the hunt
recovered something unusually sensitive (a LAPS password seen in a response, a gMSA blob).
Do not soften the CAUTION block, and do not drop it because a particular hunt found
nothing — a clean hunt's folder still lists the indicators that were checked.

**The README states a handling posture, never a verdict.** A hunt surfaces candidates, and
a good proportion of them turn out to be benign — a GPO refresh that looks like a dump, a
stale machine password that looks like brute force, a broken computer account that looks
like anonymous recon. Do not write that this folder contains attacker activity, hostile
infrastructure or a confirmed compromise: that claim belongs in the report, where it is
argued from evidence and can say "assessed benign" just as easily.

**Keep this file free of tool, vendor and workflow instructions.** It is a hazard label for
whoever opens the folder, not a policy document. What may and may not be done with the
data lives in this routine's *Data handling* section — not in a README that travels with
the evidence.


### Always pretty-print the finished report — the last act of the routine

**Render the report at the end of every run, unprompted.** A file path is not a delivery.

```bash
python3 "$plugin_dir/tools/mdpretty.py" "$report_dir/hunt-ldap-report.md"
```

**Shell output is not reliably shown to the user** — it goes to the model. After rendering,
**reproduce the report in your own reply message as Markdown**, which is what the user
actually reads. If the user has to ask for the report a second time, it was not delivered.


---

## Clean up and housekeeping

**Scratch is deleted. Evidence is kept.** The prefiltered JSONL holds every bind blob in
the log — credential material — so it must not outlive the run. Run this at the end of
every hunt, and after an aborted one.

| Keep — the deliverable | Delete — scratch |
|---|---|
| `$report_dir/hunt-ldap-report.md` and `README.md` | `$tmp/ldap-pre.json` and `$tmp/pivot.json` |
| `$report_dir/artifacts/*` and its `sha256sums.txt` | Ad-hoc Python/`jq` scripts written to run one pass |
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

- **Restrictive permissions** — scratch holds NTLM/Kerberos tokens and internal
  addressing on a possibly shared host. `umask 077` before writing anything sensitive.
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

### Resource housekeeping on large logs

- **Stream, never slurp.** One `grep` prefilter, one streaming Python pass. Never `jq -s`,
  never `json.load(open(...))`.
- **Run the script with `python3 -I`** so nothing beside the log or in the working
  directory can shadow a standard-library module.
- **The script bounds itself**: top-N flow lists, every row list capped at 50 000, every
  per-key set at 2 000, every counter at 200 000 keys. An enormous or hostile log cannot
  exhaust RAM, and anything dropped is counted in the `WARNING: caps reached` line.
- **Check free space** before writing artifacts: `df -h "$report_dir"`.

### Final checklist — print the outcome, don't just do it

```bash
cd "$report_dir/artifacts" && sha256sum -- $(ls | grep -vx sha256sums.txt) > sha256sums.txt
[ -n "$tmp" ] && [ -d "$tmp" ] && rm -rf "$tmp"
ls -la "$report_dir" "$report_dir/artifacts"
```

- [ ] Report written to `$report_dir/hunt-ldap-report.md`
- [ ] `$report_dir/README.md` written, with the CAUTION block intact
- [ ] Report pretty-printed **and reproduced in the reply message** — not just a path
- [ ] Every supporting file in `$report_dir/artifacts/`, nothing loose elsewhere
- [ ] `artifacts/sha256sums.txt` written, covering every artifact but itself, and `sha256sum -c` passes
- [ ] No NTLM/Kerberos response bytes in the report, the artifacts or the terminal excerpts
- [ ] No secret attribute values, PasswordModify values or compare assertions anywhere: every `ldap` excerpt went through `redact.jq`
- [ ] Source `eve.json` unmodified — same size, same mtime
- [ ] Scratch dir removed — the prefiltered bind blobs are gone
- [ ] Nothing left the machine (see *Data handling*)
- [ ] Summary table and raw evidence excerpts printed to the terminal
- [ ] Case folder path stated to the user
