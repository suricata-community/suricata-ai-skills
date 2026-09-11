# Suricata AI Skills

AI **Skill** files for [Suricata](https://suricata.io/).

> Suricata is a high performance, open source network analysis and threat detection
> software used by most private and public organizations, and embedded by major vendors
> to protect their assets.

A skill is a Markdown file (`SKILL.md`) with YAML frontmatter: the frontmatter says when
the skill applies, the body is the procedure the agent follows. An AI agent — Claude Code
and others reading the same format — loads a skill only when the task matches, so a large
library costs nothing until it is relevant.


## Skill groups

**Threat hunting (`hunt/`) is the first group. New additions will follow. It is not the only planned group** —
further groups will cover Suricata configuration, tuning, performance troubleshooting,
rule writing and more.

### `hunt/` — threat hunting over Suricata EVE JSON

A router skill that profiles a log and dispatches to specialised routines, then merges
their findings into one report.

| Skill | Covers |
|---|---|
| `hunt/` | Router: log profiling, case-folder conventions, routine selection, merged report |
| `hunt/skills/hunt-generic/` | Broad sweep — alerts, HTTP-to-IP, risky TLDs, large transfers, DNS anomalies, rare ports, beaconing, internal recon |
| `hunt/skills/hunt-dns-tunnel/` | DNS tunnelling — TXT base64 exfiltration and dnscat2-style hex-QNAME C2, with payload decoding |
| `hunt/skills/hunt-tls-c2/` | Malicious TLS — DGA SNI, bad and self-signed certificates, long-lived C2 flows, JA3/JA4 pivots |
| `hunt/skills/hunt-smb-dcerpc/` | SMB/DCERPC — EternalBlue, PsExec, password spray, DCSync, Zerologon, RPC coercion |

`hunt/tools/mdpretty.py` renders a finished report in the terminal, no Markdown viewer
needed.

---

## Example

The input is an EVE JSON log, not a capture. If you have only a capture, produce a log
from it first:

```bash
suricata -r capture.pcap -l ./out
```

Then hunt it — by name, or just describe the task and let the agent route:

```
/hunt ./out/eve.json
/hunt-dns-tunnel /var/log/suricata/eve.json
```

The router profiles the log, runs the routines that have data to work with, and writes a
case folder beside it:

```
report-jokerdns-hunt-dns-tunnel-20260829-1326/
├── README.md                 handling warning for whoever opens this later
├── hunt-report.md            the findings
└── artifacts/                decoded payloads, IOC lists, sha256sums.txt
```

To install, place a skill where your agent looks for it — a project's `.claude/skills/`,
your personal `~/.claude/skills/`, or a plugin directory, example:

```
claude --plugin-dir /path/to/suricata-ai-skills
```

## Contributing

New skills are welcome, in any group. Open a pull request.

---

## License

GPL-2.0. See [LICENSE.txt](LICENSE.txt).
