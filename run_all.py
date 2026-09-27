"""
Single entry point — runs the whole pipeline:
download -> Flume-style capture -> Spark analysis (PySpark + Spark SQL)
-> chart & summary generation

Usage:
    python run_all.py
"""
from download_dataset import download
from flume_style_ingest import ingest
from spark_analysis import run
from visualize_reports import main as generate_visuals

if __name__ == "__main__":
    print("STEP 1/4: Downloading dataset...")
    download()

    print("\nSTEP 2/4: Ingesting (Flume-style capture)...")
    ingest()

    print("\nSTEP 3/4: Running Spark analysis...")
    run()

    print("\nSTEP 4/4: Generating charts and summary report...")
    generate_visuals()

    print("\nAll done. Check the 'output/' folder for results, "
          "or run `streamlit run dashboard.py` to explore interactively.")
