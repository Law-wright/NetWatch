# NetWatch

NetWatch is a local network security monitoring project. Phase 1 is a dark Streamlit dashboard that summarizes a seeded set of fictional packet metadata. Later phases will add offline PCAP analysis, Windows security events, SQLite storage, and rule-based detection.

This is a portfolio and learning project. It is not a production IDS, and it does not capture live traffic.

## Phase 1 status

Implemented now:

- Seeded fictional packet metadata (800 rows, fixed 30-minute UTC window)
- Overview metrics and a packets-over-time chart
- Protocol, top address, and port charts
- Filters for IP address, protocol, port, and time
- A metadata table with a visible simulated-data label
- Unit tests for the generator, record contracts, and filters

Not implemented yet:

- PCAP upload and Scapy parsing (Phase 2)
- Windows and Sysmon event ingestion (Phase 3)
- SQLite persistence (Phase 3)
- Detection rules and alerts (Phase 4)
- Investigation workflow and screenshots (Phase 5)

## Simulated data

Every packet in this phase is generated in memory with a fixed random seed. Addresses come from [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation ranges and [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) private ranges. The dashboard banner states that the rows are fictional. They are not a capture from this computer or any live network.

The application does not send data off the machine. There is no telemetry and no threat-intelligence lookup.

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

The tests call the generator and filter functions directly. They do not start Streamlit and they do not use the network.

In the dashboard, Overview shows the full seeded set. On Network Traffic:

- IP `192.0.2.10` narrows the table to packets involving that documentation address.
- IP `192.0.2.199` is valid and outside the seeded set, so the table is empty.
- Protocol, port, and the UTC time slider narrow the same table.

## Project layout

```text
NetWatch/
├── app.py                     # Streamlit entry point and localhost navigation
├── core/
│   ├── models.py              # Packet, event, rule, and alert records
│   ├── sample_data.py         # Seeded fictional traffic
│   └── filters.py             # Filter and summary functions
├── dashboard/
│   ├── common.py              # Banner, chart styling, table formatting
│   ├── overview.py            # Metrics and packets over time
│   └── network.py             # Charts, filters, and the packet table
├── data/                      # Future local databases and captures (gitignored)
├── tests/
├── .streamlit/config.toml     # Loopback bind, dark theme, upload cap
├── requirements.txt
├── LICENSE
└── README.md
```

Upcoming modules, not present until their phase: `core/packet_analyzer.py`, `core/log_analyzer.py`, `core/detection_engine.py`, `core/database.py`, `dashboard/security_events.py`, `dashboard/alerts.py`, and `dashboard/investigation.py`.

## Roadmap

1. **Simulated traffic dashboard.** This phase.
2. **Offline PCAP analysis.** Upload a saved capture and parse metadata with Scapy. Live capture stays off unless you explicitly approve it.
3. **Windows events and SQLite.** Simulated security events first, then an optional local log reader that handles missing channels and access denied.
4. **Detection engine.** Failed authentication, possible port scanning, volume change, and user-defined watch rules. Alert text will describe behavior, not a confirmed attack.
5. **Investigation and portfolio polish.** Alert status, evidence review, architecture notes, and screenshots of the seeded scenario.

## License

MIT. See [LICENSE](LICENSE).
