"""
Single entry point — runs the whole pipeline:
download -> Flume-style capture -> Spark/Hive-SQL analysis

Usage:
    python run_all.py
"""
from download_dataset import download
from flume_style_ingest import ingest
from spark_analysis import run

if __name__ == "__main__":
    print("STEP 1/3: Downloading dataset...")
    download()

    print("\nSTEP 2/3: Ingesting (Flume-style capture)...")
    ingest()

    print("\nSTEP 3/3: Running Spark/Hive-SQL analysis...")
    run()

    print("\nAll done. Check the 'output/' folder for results.")
