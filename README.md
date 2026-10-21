# NetWatch

NetWatch is a local network security monitoring project. It is a dark Streamlit dashboard for a seeded set of fictional packet metadata and fictional Windows events. It can also summarize a PCAP or PCAPNG file you upload, and it can read local Windows logs when you ask. A later phase will add rule-based detection.

This is a portfolio and learning project. It is not a production IDS, and it does not capture live traffic.

## Current status

Implemented now:

- Seeded fictional packet metadata (800 rows, fixed 30-minute UTC window)
- Overview metrics and a packets-over-time chart
- Protocol, top address, and port charts
- Filters for IP address, protocol, port, and time
- A metadata table with a visible data-origin label
- Offline PCAP and PCAPNG upload, parsed with Scapy into that same table
- A 50 MB upload cap and a 100,000 packet cap
- Seeded fictional security events (80 rows, same 30-minute UTC window, including eight failed logons)
- A Security Events page with filters and an events-over-time chart
- Optional local read of the Security, System, Application, and Sysmon channels
- Missing channels and access denials are reported and skipped
- SQLite persistence for the active packet set and the active event set (`data/netwatch.db`)
- Unit tests for the generator, record contracts, filters, capture parser, event reader, and database

Not implemented yet:

- Detection rules and alerts (Phase 4)
- Investigation workflow and screenshots (Phase 5)

## Simulated data

Every packet in the demonstration set is generated in memory with a fixed random seed. Addresses come from [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation ranges and [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) private ranges. While that set is loaded, the dashboard banner states that the rows are fictional. They are not a capture from this computer or any live network.

The application does not send data off the machine. There is no telemetry and no threat-intelligence lookup.

## Offline captures

The sidebar accepts one `.pcap`, `.pcapng`, or `.cap` file, up to 50 MB. Parsing happens in memory on this computer. The capture is not written into the repository and is not sent anywhere.

Scapy reads the saved packets. NetWatch keeps timestamp, addresses, protocol, ports, length, IP version, and TCP flags. It does not keep payload bytes. Packets without usable IP metadata are counted and skipped. A capture with more than 100,000 acceptable packets keeps the first 100,000.

The table column "Data origin" reads "Imported" for these rows. "Use simulated data" loads the fictional set again. The imported metadata is saved in the local database and shown again on the next launch. Live capture is not implemented. Reading a saved file does not require Npcap.

## Windows events

Security Events opens on a seeded fictional log. The accounts are `demo.user`, `svc.backup`, and `lab.admin`. Addresses stay inside the same documentation and private ranges as the packets. Eight rows are failed logons for `demo.user` from `192.0.2.25`. While that set is loaded, the banner says the rows are fictional.

"Read local Windows logs" queries four channels with `wevtutil`: Security, System, Application, and Sysmon (`Microsoft-Windows-Sysmon/Operational`). The query is read-only. NetWatch does not clear logs and does not capture live traffic.

If Windows refuses a channel, or the channel is not installed, that channel is reported and skipped. A read that keeps nothing leaves the current event set in place. The Security channel often refuses readers that are not elevated. Sysmon is absent unless it is installed.

For the events it keeps, NetWatch stores time, channel, provider, event id, account, addresses, ports, the process file name, the parent file name, process id, logon type, and a fixed summary sentence such as "Failed logon." It does not store command lines, free-text messages, passwords, or payload bytes. "Use simulated events" loads the fictional set again.

## Local database

The active packet set and the active event set are stored in `data/netwatch.db`. That file is gitignored. Restarting the dashboard loads it. There is one packet set and one event set at a time: an upload, a local log read, or a return to simulated data replaces the rows it owns.

Tests set `NETWATCH_DB` to a temporary file so they do not use the dashboard database.

## Local use only

Streamlit is configured to listen on `127.0.0.1` port `8501`, with CORS protection enabled and allowed hosts limited to `localhost` and `127.0.0.1`. In Streamlit 1.66, `server.enableCORS = false` allows every origin, so the project config leaves protection on. Keep the bind address on loopback. Do not expose the dashboard to the internet. Windows 10 is past its standard support date; NetWatch stays offline.

## Requirements

- Windows 10 or later
- Python 3.12
- PowerShell

On this machine, `python` is the Microsoft Store alias and does not run Python 3.12. Use `py -3.12` to create the virtual environment, then the environment's `python.exe`.

## Setup

Run these commands in PowerShell from the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

If activation is blocked by execution policy, you do not need to change that policy. Call `.\.venv\Scripts\python.exe` directly, as the commands above do.

## Run

PowerShell, from the repository root:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

Open http://127.0.0.1:8501 in a browser on this computer.

## Test

PowerShell, from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Generator, filter, parser, event, and database tests call those functions directly. They build small captures in memory and do not send packets. They do not query this computer's Windows logs; the reader tests pass in XML and canned status text. Dashboard tests set `NETWATCH_DB` to a temporary file. One test runs the dashboard through Streamlit's app runner to confirm an upload replaces the fictional packet set and a file that is not a capture leaves that set in place. Another confirms Security Events can switch to a canned local read and back to the fictional log.

In the dashboard, Overview shows the full seeded set. On Network Traffic:

- IP `192.0.2.10` narrows the table to packets involving that documentation address.
- IP `192.0.2.199` is valid and outside the seeded set, so the table is empty.
- Protocol, port, and the UTC time slider narrow the same table.

On Security Events, the fictional set includes failed logons for `192.0.2.25`. Outcome, channel, event id, account, IP, and the UTC time slider narrow that table. "Read local Windows logs" reports each channel. Access denied, or a missing Sysmon channel, leaves the fictional set in place when nothing was kept.

## Inspect a saved capture

Start the dashboard, then use "Offline capture" in the sidebar. After a successful import, Overview and Network Traffic describe that file. "Use simulated data" loads the 800-row demonstration set again.

A file that is not a PCAP or PCAPNG leaves the current packet table in place and shows an error in the sidebar.

## Project layout

```text
NetWatch/
├── app.py                     # Streamlit entry point and localhost navigation
├── core/
│   ├── models.py              # Packet, event, rule, and alert records
│   ├── sample_data.py         # Seeded fictional traffic
│   ├── packet_analyzer.py     # Offline PCAP and PCAPNG metadata
│   ├── log_analyzer.py        # Fictional events and read-only Windows logs
│   ├── database.py            # Local SQLite store
│   └── filters.py             # Filter and summary functions
├── dashboard/
│   ├── common.py              # Banner, chart styling, table formatting
│   ├── state.py               # Session state and database loads
│   ├── overview.py            # Metrics and packets over time
│   ├── network.py             # Charts, filters, and the packet table
│   └── security_events.py     # Event filters, chart, and local log read
├── data/                      # Local database and captures (gitignored)
├── tests/
├── .streamlit/config.toml     # Loopback bind, dark theme, upload cap
├── requirements.txt
├── LICENSE
└── README.md
```

Upcoming modules, not present until their phase: `core/detection_engine.py`, `dashboard/alerts.py`, and `dashboard/investigation.py`.

## Roadmap

1. **Simulated traffic dashboard.** Done.
2. **Offline PCAP analysis.** Done. Upload a saved capture and parse metadata with Scapy. Live capture stays off.
3. **Windows events and SQLite.** Done. Fictional security events, an optional local log reader that handles missing channels and access denied, and a local SQLite file for the active packet and event sets.
4. **Detection engine.** Failed authentication, possible port scanning, volume change, and user-defined watch rules. Alert text will describe behavior, not a confirmed attack.
5. **Investigation and portfolio polish.** Alert status, evidence review, architecture notes, and screenshots of the seeded scenario.

## License

MIT. See [LICENSE](LICENSE).
