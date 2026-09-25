# bda-mini_project
# Big Data Analytics Mini Project — Weblog Intrusion Analysis (Python version)

## Aim
Case study on a real-life large data application: streaming weblog analysis
using Flume-style capture and Hive/PySpark-style analysis, applied to detect
intrusion/recon patterns in server logs.

## Dataset
NASA-HTTP access logs — Kennedy Space Center WWW server, July 1995 (~1.3M requests).

## Tools Used (mapped to plain Python + PySpark, no cluster setup needed)
- **Flume (capture)** → `flume_style_ingest.py` — mimics Flume's spooling-directory
  behavior: watches the raw data folder and lands files into an "ingested" folder,
  the same job Flume does before handing data to Hadoop.
- **Hive (analysis)** → Spark SQL, run inside PySpark. Spark SQL is HiveQL-compatible,
  so the same queries you'd run in Hive run here through `spark.sql(...)`.
- **PySpark** → `spark_analysis.py` — parses the logs and runs the queries.

## Setup
```bash
# Java is required by Spark
sudo pacman -S jdk-openjdk     # Arch
# or: sudo dnf install java-1.8.0-openjdk   # Rocky

pip install -r requirements.txt
```

## Run (one command)
```bash
python run_all.py
```
This downloads the dataset, runs the Flume-style capture step, then runs the
Spark/Hive-SQL analysis and prints results to the terminal.

## Output
- Console: top IPs, suspicious scanning IPs (404 bursts), status code
  distribution, HTTP method distribution.
- File: `output/suspicious_ips/*.csv` — the flagged scanning IPs.

## Project Files
| File | Role |
|---|---|
| `download_dataset.py` | Fetches the NASA-HTTP dataset |
| `flume_style_ingest.py` | Flume-equivalent capture step |
| `spark_analysis.py` | Hive/PySpark-equivalent analysis (Spark SQL) |
| `run_all.py` | Runs the full pipeline in one command |
| `requirements.txt` | Python dependencies (pyspark) |

