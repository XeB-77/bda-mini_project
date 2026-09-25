"""
Downloads the NASA-HTTP access log dataset (Kennedy Space Center, July 1995).
"""
import os
import gzip
import shutil
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "raw")
URL = "https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz"
GZ_PATH = os.path.join(DATA_DIR, "NASA_access_log_Jul95.gz")
LOG_PATH = os.path.join(DATA_DIR, "NASA_access_log_Jul95")


def download():
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(LOG_PATH):
        print(f"Dataset already present: {LOG_PATH}")
        return LOG_PATH

    print("Downloading NASA-HTTP access log dataset...")
    try:
        urllib.request.urlretrieve(URL, GZ_PATH)
    except Exception as e:
        raise SystemExit(
            "Download failed (this 1995 archive link is often unreliable).\n"
            "Fix: search Kaggle for 'NASA access log' / 'NASA-HTTP', download it, "
            f"and place the file at: {LOG_PATH}\n"
            f"Original error: {e}"
        )

    print("Extracting...")
    with gzip.open(GZ_PATH, "rb") as f_in, open(LOG_PATH, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)

    print(f"Done: {LOG_PATH}")
    return LOG_PATH


if __name__ == "__main__":
    download()
