# NetWatch Threat Model

Method: STRIDE for the tool itself, plus a detection-coverage map.
Last reviewed: November 2026

## Scope

A local Streamlit analyst dashboard that explores packet metadata and Windows
security events, stores one active packet set and one active event set in
SQLite, and raises evidence-linked findings from rule checks. It is a
portfolio and learning project, not a production IDS. It does not capture
live traffic, keep payload bytes, or send data off the machine.

**In scope**

- Seeded fictional packets and events, or one offline PCAP / PCAPNG / CAP upload
- Optional read-only `wevtutil` queries of Security, System, Application, and Sysmon
- Built-in detection (failed authentication, possible port scanning, volume change)
  and user-defined watches
- Investigation triage with related rows rebuilt from evidence references

**Out of scope**

- Live packet capture or Npcap-based sniffing
- Encrypted payload inspection, command lines, free-text log messages, passwords
- Threat-intelligence lookups or network exposure of the dashboard
- Tamper-evident storage, multi-user auth, or remote collection agents

**Stack:** Python 3.12, Streamlit (loopback), Scapy, SQLite, pandas, Plotly, pytest;
Windows host tooling via PowerShell and `wevtutil`.

## Part A: What NetWatch detects

Findings describe patterns in the loaded metadata. Severity is a review label.
Alert text does not call a finding a confirmed attack.

| Attacker behavior | MITRE ATT&CK | Rule (defaults) | Validated with |
| --- | --- | --- | --- |
| Password guessing / repeated failed logons | T1110.001 | `failed_auth` — 5 failed logons (event 4625) for the same account and source address in 300 s | Seeded set: 8 failed logons for `demo.user` from `192.0.2.25`; detection tests |
| Network service discovery (port scan style) | T1046 | `possible_port_scan` — 15 distinct TCP SYN destination ports from one source to one host in 60 s | Seeded SYN burst from `10.0.0.18` to `203.0.113.80` on ports 2000–2019; detection tests |
| Sharp traffic volume change (flooding or bulk transfer heuristic) | No single technique asserted; often discussed with T1498 or T1048 | `volume_change` — a 60 s bucket at least 3× the median of other buckets and at least 40 packets | Seeded one-minute increase (80 packets); detection tests |
| Analyst-defined field match | Depends on the watch | `watch_*` — match packets or events on address, protocol, port, account, event id, and/or outcome | Watch parameter tests and Alerts UI |

### Detection gaps (what it will miss)

- Slow-and-low activity that stays under the configured thresholds
- Anything that requires payload, decryption, or full packet contents (metadata only)
- Activity that never appears in the loaded packet set or the four Windows channels
- Attackers who clear or tamper with Windows logs before a local read
- Patterns outside the three built-ins and whatever watches the analyst defines
- Static thresholds only — no per-host baselining

## Part B: Threats to NetWatch itself

| # | Threat (STRIDE) | Example attack | Mitigation in this project |
| --- | --- | --- | --- |
| 1 | Tampering | Someone edits `data/netwatch.db` to hide or invent rows | Database is local and gitignored; no remote sync. **Gap:** no hash-chaining or integrity checks on stored rows |
| 2 | Tampering | Malformed PCAP crashes or confuses the parser | Offline upload only; magic-byte check before Scapy; 50 MB size cap; 100,000-packet cap; parser and dashboard tests reject bad files without replacing the current set |
| 3 | Information disclosure | Packet or event data leaves the machine or exposes secrets | Loopback bind (`127.0.0.1`), CORS left on, `allowedHosts` limited; metadata-only models (no payloads, passwords, or command lines); no telemetry |
| 4 | Elevation of privilege | Log reader abuses host access | `wevtutil` collection is read-only; NetWatch does not clear logs. Channel access still depends on Windows rights |
| 5 | Spoofing | Forged events or a crafted PCAP inject false findings | User-supplied captures and local logs are treated as data the analyst chose to load, not as authenticated evidence. Simulated rows are labeled fictional. Rule parameters are validated; findings keep evidence references for review |
| 6 | Denial of service | Oversized capture exhausts memory | 50 MB upload cap (Streamlit config and parser) and 100,000 acceptable-packet cap |
| 7 | Repudiation | Analyst cannot show what a finding referred to | Findings store evidence fields; Investigation rebuilds related packet or event rows; triage status (`open` / `acknowledged` / `dismissed`) is kept across re-detect for the same `alert_uid` |
| 8 | Spoofing / information disclosure | Untrusted peer reaches the dashboard | Intended for local use only. No dashboard login. Do not bind to `0.0.0.0` or expose the port |

## Known gaps and next steps

- Thresholds are static. Baselining per host is not implemented.
- No tamper-evident storage (for example hash-chaining stored events or alerts).
- No dashboard authentication; trust model is “operator on loopback.”
- Volume change is a heuristic, not a mapped claim of exfiltration or DoS.
- Watch rules and further ATT&CK coverage (for example T1078 valid accounts) remain analyst-defined extensions, not shipped built-ins.
- Replacing the active packet or event set overwrites that domain’s rows; prior sets are not retained as an audit trail.

## Related project docs

- [README.md](README.md) — purpose, limitations, detection defaults, and example investigations
- `core/detection_engine.py` — rule parameters and evaluation
- `core/packet_analyzer.py` — upload size and packet caps
- `.streamlit/config.toml` — loopback bind and CORS settings
