# Weblog Intrusion Analysis

A Big Data Analytics mini project that analyzes the classic **NASA-HTTP
access log** dataset (Kennedy Space Center WWW server, July 1995) with
PySpark, surfaces suspicious traffic patterns with a rule-based heuristic,
and presents everything in an interactive Streamlit dashboard.

## Problem Statement & Objectives

Web server access logs contain a record of every request a server
receives. At scale, spotting patterns that merit human review — traffic
bursts, scanning behavior, high error rates from a single client — by
hand is impractical. This project:

1. Ingests and parses a large historical weblog dataset with PySpark.
2. Computes traffic, error, and per-client behavior statistics.
3. Flags candidate hosts for investigation using explicit, documented
   heuristic rules (see **Detection Methodology** below).
4. Presents the results in a dashboard for interactive exploration.

**This is historical log analysis, not live intrusion detection.** The
suspicious-IP output is a heuristic starting point for a human reviewer,
not a verdict, and several of the top-flagged hosts in this dataset are
shared 1995-era proxy gateways (AOL, Prodigy) rather than anything
malicious — see Known Limitations.

## Dataset

- **Source:** NASA-HTTP access logs, Kennedy Space Center WWW server,
  July 1–31, 1995 (the standard public "NASA-HTTP" trace).
- **Format:** NCSA Common Log Format —
  `host ident authuser [timestamp] "method path protocol" status bytes`.
- ~1.89 million raw log lines.
- **Limitations of the dataset itself:** it is 30 years old, HTTP-only
  (no HTTPS, no modern attack patterns), and a small fraction of lines
  (~0.1%) are genuinely malformed regardless of parser leniency.

## Technologies Used

| Purpose | Technology |
|---|---|
| Distributed / large-scale processing | PySpark (DataFrame API + Spark SQL) |
| Ingestion simulation | Custom Flume-style script (see note below) |
| Static charts & summary report | Pandas + Matplotlib |
| Interactive dashboard | Streamlit + Plotly |
| Live packet capture (standalone demo) | Scapy |

**Naming note:** `flume_style_ingest.py` simulates the *behavior* of a
Flume ingestion stage (moving a file into an "ingested" landing zone with
a `.COMPLETED` marker); it does not run Apache Flume itself. Several
aggregations in `spark_analysis.py` use genuine `spark.sql()` queries
against a registered temp view (Spark SQL is HiveQL-compatible), and the
rest use the equivalent DataFrame API, which compiles to the same
Catalyst query plan.

## System Architecture

```
download_dataset.py  →  flume_style_ingest.py  →  spark_analysis.py  →  visualize_reports.py  →  dashboard.py
   (fetch + unzip)        (simulate landing)        (PySpark ETL +         (matplotlib PNGs +      (Streamlit app,
                                                       Spark SQL +           summary_report.txt)     reads the same
                                                       CSV reports)                                  CSV reports)

network_monitor.py  (standalone, NOT connected to the pipeline above — see below)
```

`run_all.py` runs the first four stages in one command.

## Data Processing Workflow

1. **Download** (`download_dataset.py`): fetches and extracts the gzipped
   NASA access log into `data/raw/`.
2. **Ingest** (`flume_style_ingest.py`): copies the raw log into
   `data/ingested/` and appends a `.COMPLETED` marker file, simulating a
   Flume-style landing zone.
3. **Analyze** (`spark_analysis.py`): the core PySpark job —
   - Parses each line with a regex (`log_patterns.py`), tolerant of the
     dataset's real-world quirk of some requests omitting the trailing
     HTTP version token.
   - Computes and **persists** a data-quality report (total / valid /
     invalid / duplicate / unparsable counts).
   - Computes HTTP status and method distributions via Spark SQL.
   - Builds a per-host behavior profile (request volume, 404s, error
     rate, unique URLs, average response size).
   - Buckets requests per host into 1-minute windows.
   - Flags suspicious hosts using the rules below.
   - Writes all of the above as CSV reports under `output/`.
4. **Visualize** (`visualize_reports.py`): reads the CSV reports (no
   PySpark needed at this stage — Pandas/Matplotlib only) and produces
   PNG charts plus `summary_report.txt` under `output/visualizations/`.
5. **Explore** (`dashboard.py`): a Streamlit app that reads the same CSV
   reports interactively, with filtering, search, and CSV export.

## Detection Methodology & Limitations

A host is flagged as **suspicious** (a candidate for human review) if any
one of these thresholds is met:

| Rule | Threshold | Rationale |
|---|---|---|
| High request burst | ≥60 requests from one host in a single 1-minute window | Consistent with automated/scripted access |
| High 404 rate | ≥20 total 404 responses | Consistent with scanning for nonexistent paths |
| High unique URL count | ≥100 distinct URLs requested | Consistent with crawling/enumeration |

**These are heuristics, not proof.** In this specific dataset, several of
the highest-volume flagged hosts (`piweba3y.prodigy.com`,
`www-a2.proxy.aol.com`, etc.) are known shared dial-up/proxy gateways from
1995 fronting many simultaneous real users — exactly the kind of
legitimate traffic that can trip a burst or unique-URL threshold. Treat
every flagged row as a lead to investigate, never as a conclusion.

## Data Quality — Definitions

The dashboard's Overview page and `output/reports/data_quality/` define:

- **Total**: every raw line read, including exact duplicate lines.
- **Valid**: lines that matched the log pattern *and* had a castable
  status code, timestamp, and byte count. Every other report in this
  project is built from this set.
- **Invalid**: total − valid. Broken down into unparsable lines (no host
  extracted at all) vs. field-level cast failures.
- **Duplicates**: exact, byte-for-byte repeated raw lines (~0.04% of this
  dataset). These are **measured but intentionally not removed** from the
  analysis — removing them would silently change historical totals, and
  at this volume they don't materially affect any result. This is stated
  explicitly rather than left implicit.

## Network Monitoring — What It Actually Does

`network_monitor.py` is a **real, standalone** live-packet-capture script
using Scapy. It is **not** connected to the rest of this pipeline: it
doesn't read from or write to `output/`, isn't called by `run_all.py`,
and nothing it produces appears in the dashboard.

- It only inspects **plain, unencrypted HTTP on port 80** — it cannot see
  HTTPS, which is the overwhelming majority of real traffic today. On a
  modern network it will typically see little or nothing.
- It requires elevated privileges to open a capture socket (`sudo`, or
  `CAP_NET_RAW`/`CAP_NET_ADMIN` via `setcap`).
- Its "baseline" request/error limits are a rough heuristic derived from
  the static NASA dataset, not a statistically validated threshold.

Run it explicitly and separately if you want to demonstrate live capture:
`python network_monitor.py [interface]`.

## Installation

**Prerequisites:**
- Python 3.10–3.14
- Java 17 or 21 (required by Spark) — check with `java -version`

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

`pyspark>=4.0.0` is required for Python 3.12+; older PySpark releases do
not support recent Python versions.

## Running the Project

**Full pipeline (download → ingest → analyze → visualize):**
```bash
python run_all.py
```

**Individual steps:**
```bash
python download_dataset.py
python flume_style_ingest.py
python spark_analysis.py
python visualize_reports.py
```

**Dashboard** (after the pipeline has produced `output/reports/` at least
once):
```bash
streamlit run dashboard.py
```

**Standalone live packet capture demo** (optional, needs elevated
privileges):
```bash
sudo python network_monitor.py
```

## Dashboard Features

| Page | What it shows |
|---|---|
| **Overview** | Dataset period, data-quality summary (valid/invalid/duplicate counts), top clients, HTTP status mix, suspicious-IP preview |
| **Traffic Analysis** | Request volume over time (15-minute buckets), per-client filtering, peak-window table |
| **Suspicious IPs** | Full flagged list, search, detection-rule explanation, reason breakdown |
| **IP Behavior** | Per-host request/error/unique-URL profiles, search & sort |
| **HTTP Errors** | Full status-code breakdown (2xx–5xx), 4xx vs 5xx split, top error sources |
| **Data Explorer** | Raw access to every generated report, with capped, downloadable CSV export |

All pages read from the CSV reports under `output/`, are cached with
`st.cache_data`, and cap table rendering / CSV export size for
responsiveness on the full ~1.89M-row dataset.

## Output Directory Structure

```
output/
├── suspicious_ips/                  # flagged hosts + reason
├── reports/
│   ├── ip_behavior_profile/         # per-host stats
│   ├── requests_per_minute/         # per-host, 1-minute windows
│   ├── status_distribution/         # HTTP status code counts + category
│   ├── method_distribution/         # HTTP method counts
│   └── data_quality/                # single-row total/valid/invalid/duplicate summary
└── visualizations/
    ├── 01_top_suspicious_ips.png
    ├── 02_requests_over_time.png
    ├── 03_top_ip_request_volume.png
    ├── 04_top_404_errors.png
    ├── 05_ip_behavior_scatter.png
    ├── 06_request_distribution.png
    ├── 07_status_distribution.png
    └── summary_report.txt
```

Each PySpark CSV report is written as a single-partition folder
(`coalesce(1)`), so each contains one `part-*.csv` file plus Spark's
`_SUCCESS`/`.crc` bookkeeping files.

## Testing & Validation

`tests/test_log_parsing.py` unit-tests the parsing regex and status
categorization in pure Python (no PySpark/Java required), including a
sanity check of the match rate against the real ingested dataset when
present:

```bash
python -m unittest tests/test_log_parsing.py -v
```

See `PROJECT_AUDIT_HANDOFF.md` for the full record of what was and
wasn't executed end-to-end during the last audit pass, and why.

## Known Limitations

- Suspicious-IP detection is heuristic and will flag legitimate shared
  infrastructure (proxies, gateways) alongside genuinely anomalous hosts.
- The dataset is 30 years old and HTTP-only; findings are illustrative of
  method, not current threat intelligence.
- `network_monitor.py` is a separate live-capture demo, not integrated
  intrusion detection, and only sees unencrypted HTTP.
- A small residual (~0.1%) of log lines remain genuinely unparsable
  after the regex fix (extra whitespace / corrupted request fields).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `spark_analysis.py` fails to start Spark | Check `java -version`; Spark needs Java 17 or 21 on the `PATH` |
| `ModuleNotFoundError: pyspark` (or streamlit/plotly/scapy) | Activate the venv and re-run `pip install -r requirements.txt` |
| Dashboard shows "data unavailable" everywhere | Run `python run_all.py` (or at least `spark_analysis.py`) first to generate `output/reports/` |
| Dashboard's Data Quality section shows a fallback message | The `output/reports/data_quality` report wasn't found — re-run `spark_analysis.py` (this report was added in this revision; older `output/` folders won't have it) |
| `network_monitor.py` exits with a permission error | Run with `sudo`, or grant capture capability: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))` |
| PySpark import errors on Python 3.13/3.14 | Ensure `pyspark>=4.0.0` is installed — earlier PySpark releases don't support these Python versions |
