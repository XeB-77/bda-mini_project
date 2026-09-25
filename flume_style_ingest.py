"""
Python stand-in for a Flume spooling-directory agent.
Real Flume watches a spool dir and lands files into HDFS on a full cluster.
This does the same *job* locally (capture -> land in a target folder) so the
whole pipeline runs with just Python + PySpark, no Hadoop/Flume install needed.
"""
import os
import shutil
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SPOOL_DIR = os.path.join(BASE_DIR, "data", "raw")
INGESTED_DIR = os.path.join(BASE_DIR, "data", "ingested")


def ingest():
    os.makedirs(INGESTED_DIR, exist_ok=True)
    files = [f for f in os.listdir(SPOOL_DIR) if not f.endswith(".gz")]
    if not files:
        raise SystemExit("No dataset found in data/raw — run download_dataset.py first.")

    for fname in files:
        src = os.path.join(SPOOL_DIR, fname)
        dst = os.path.join(INGESTED_DIR, fname + ".COMPLETED")
        print(f"[ingest] capturing {fname} -> {os.path.basename(dst)}")
        shutil.copyfile(src, dst)
        time.sleep(0.2)  # simulate streaming capture

    print(f"Ingestion complete. Files landed in: {INGESTED_DIR}")
    return INGESTED_DIR


if __name__ == "__main__":
    ingest()
