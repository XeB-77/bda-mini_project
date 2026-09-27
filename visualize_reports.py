
import os
import re
import glob
import warnings
from pathlib import Path

import pandas as pd
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

warnings.filterwarnings("ignore", category=UserWarning)

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = BASE_DIR / "output"
SUSPICIOUS_DIR = OUTPUT_DIR / "suspicious_ips"
REPORT_DIR = OUTPUT_DIR / "reports"

VISUALIZATION_DIR = OUTPUT_DIR / "visualizations"
VISUALIZATION_DIR.mkdir(parents=True, exist_ok=True)

TOP_N = 15

plt.rcParams.update({
    "figure.figsize": (13, 7),
    "figure.dpi": 120,
    "savefig.dpi": 160,
    "axes.titlesize": 16,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 10,
})


# ============================================================
# GENERAL HELPERS
# ============================================================

def normalize_column(name):
    """Normalize a column name for flexible matching."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def find_column(df, candidates):
    """Find the first matching column from a list of possible names."""
    normalized = {
        normalize_column(column): column
        for column in df.columns
    }

    for candidate in candidates:
        key = normalize_column(candidate)
        if key in normalized:
            return normalized[key]

    # Fallback: allow partial matching.
    for candidate in candidates:
        key = normalize_column(candidate)
        for normalized_name, original_name in normalized.items():
            if key and key in normalized_name:
                return original_name

    return None


def read_spark_csv(folder):
    """
    Read Spark CSV output folders containing part-*.csv files.
    Also supports a regular CSV file.
    """
    folder = Path(folder)

    if not folder.exists():
        print(f"[SKIP] Folder not found: {folder}")
        return pd.DataFrame()

    if folder.is_file() and folder.suffix.lower() == ".csv":
        files = [folder]
    else:
        files = sorted(folder.rglob("part-*.csv"))

    if not files:
        print(f"[SKIP] No part-*.csv files found in: {folder}")
        return pd.DataFrame()

    frames = []

    for file in files:
        try:
            frame = pd.read_csv(file)
            if not frame.empty:
                frames.append(frame)
        except Exception as error:
            print(f"[WARNING] Could not read {file.name}: {error}")

    if not frames:
        return pd.DataFrame()

    df = pd.concat(frames, ignore_index=True)
    df.columns = [str(c).strip() for c in df.columns]

    print(f"[LOADED] {folder.name}: {len(df):,} rows")
    print(f"         Columns: {list(df.columns)}")

    return df


def save_chart(filename):
    """Save the current Matplotlib figure."""
    path = VISUALIZATION_DIR / filename
    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"[SAVED] {path}")


def clean_numeric(series):
    """Convert a series into numeric values."""
    return pd.to_numeric(series, errors="coerce").fillna(0)


def clean_label(series):
    return series.fillna("Unknown").astype(str)


def format_number(value):
    return f"{value:,.0f}"


def no_data_message(chart_name, reason):
    print(f"[SKIP] {chart_name}: {reason}")


# ============================================================
# CHART 1: TOP SUSPICIOUS IPS
# ============================================================

def plot_suspicious_ips(df):
    if df.empty:
        no_data_message("Suspicious IP chart", "No suspicious IP data.")
        return

    ip_col = find_column(df, [
        "host", "ip", "ip_address", "client_ip", "source_ip"
    ])

    score_col = find_column(df, [
        "total_requests", "request_count", "requests",
        "requests_per_minute", "request_rate",
        "not_found_404", "error_404_count", "unique_urls"
    ])

    if ip_col is None:
        no_data_message("Suspicious IP chart", "IP column not found.")
        return

    if score_col is None:
        no_data_message(
            "Suspicious IP chart",
            "No suitable numeric metric found."
        )
        return

    data = df.copy()
    data[score_col] = clean_numeric(data[score_col])
    data[ip_col] = clean_label(data[ip_col])

    data = data.nlargest(TOP_N, score_col).sort_values(score_col)

    if data.empty:
        return

    plt.figure(figsize=(13, max(6, len(data) * 0.42)))

    bars = plt.barh(
        data[ip_col],
        data[score_col],
        edgecolor="black",
        linewidth=0.3
    )

    plt.title("Top Suspicious IP Addresses")
    plt.xlabel(score_col.replace("_", " ").title())
    plt.ylabel("IP Address")

    for bar, value in zip(bars, data[score_col]):
        plt.text(
            bar.get_width(),
            bar.get_y() + bar.get_height() / 2,
            f" {value:,.0f}",
            va="center",
            fontsize=9
        )

    save_chart("01_top_suspicious_ips.png")


# ============================================================
# CHART 2: REQUESTS PER MINUTE
# ============================================================

def plot_requests_per_minute(df):
    if df.empty:
        no_data_message("Traffic timeline", "No request-window data.")
        return

    ip_col = find_column(df, [
        "host", "ip", "ip_address", "client_ip"
    ])

    time_col = find_column(df, [
        "window_start", "timestamp", "time", "request_time"
    ])

    count_col = find_column(df, [
        "requests_per_minute", "request_count",
        "requests", "count", "total_requests"
    ])

    if time_col is None or count_col is None:
        no_data_message(
            "Traffic timeline",
            f"Required time/count columns missing. Found: {list(df.columns)}"
        )
        return

    data = df.copy()
    data[time_col] = pd.to_datetime(data[time_col], errors="coerce")
    data[count_col] = clean_numeric(data[count_col])
    data = data.dropna(subset=[time_col])

    if data.empty:
        no_data_message("Traffic timeline", "No valid timestamps.")
        return

    plt.figure(figsize=(15, 7))

    # The underlying data is minute-level across the whole analysis period.
    # Plotting every minute for a multi-week span produces an unreadable,
    # overlapping tangle of lines, so aggregate to daily totals for this
    # overview chart (the dashboard's Traffic Analysis page still offers
    # finer, filterable time buckets interactively).
    data["day"] = data[time_col].dt.floor("D")

    if ip_col is not None:
        data[ip_col] = clean_label(data[ip_col])

        top_ips = (
            data.groupby(ip_col)[count_col]
            .sum()
            .nlargest(5)
            .index
        )

        selected = data[data[ip_col].isin(top_ips)]
        daily = (
            selected.groupby([ip_col, "day"], as_index=False)[count_col]
            .sum()
        )

        for ip, group in daily.groupby(ip_col):
            group = group.sort_values("day")
            plt.plot(
                group["day"],
                group[count_col],
                label=ip,
                linewidth=1.8,
                marker="o",
                markersize=3,
                alpha=0.85
            )
    else:
        daily = data.groupby("day", as_index=False)[count_col].sum()
        daily = daily.sort_values("day")
        plt.plot(
            daily["day"],
            daily[count_col],
            linewidth=2,
            marker="o",
            markersize=3,
            label="Total requests"
        )

    plt.title("Daily Request Volume Over Time (Top 5 Clients)")
    plt.xlabel("Date")
    plt.ylabel("Requests per day")
    plt.gca().xaxis.set_major_formatter(
        mdates.DateFormatter("%Y-%m-%d")
    )
    plt.gcf().autofmt_xdate()
    plt.grid(True, alpha=0.25)

    if ip_col is not None:
        plt.legend(title="Client IP", loc="upper left", fontsize=8)

    save_chart("02_requests_over_time.png")


# ============================================================
# CHART 3: TOP IPS BY REQUEST VOLUME
# ============================================================

def plot_top_ip_volume(df):
    if df.empty:
        no_data_message("Top IP volume", "No IP profile data.")
        return

    ip_col = find_column(df, [
        "host", "ip", "ip_address", "client_ip", "source_ip"
    ])

    request_col = find_column(df, [
        "total_requests", "request_count", "requests", "total"
    ])

    if ip_col is None or request_col is None:
        no_data_message(
            "Top IP volume",
            f"Required columns missing. Found: {list(df.columns)}"
        )
        return

    data = df.copy()
    data[ip_col] = clean_label(data[ip_col])
    data[request_col] = clean_numeric(data[request_col])
    data = data.nlargest(TOP_N, request_col).sort_values(request_col)

    plt.figure(figsize=(13, max(6, len(data) * 0.42)))

    plt.barh(
        data[ip_col],
        data[request_col],
        edgecolor="black",
        linewidth=0.3
    )

    plt.title("Top Client IPs by Request Volume")
    plt.xlabel("Total Requests")
    plt.ylabel("Client IP")

    save_chart("03_top_ip_request_volume.png")


# ============================================================
# CHART 4: 404 ERROR ANALYSIS
# ============================================================

def plot_404_analysis(df):
    if df.empty:
        no_data_message("404 analysis", "No IP profile data.")
        return

    ip_col = find_column(df, [
        "host", "ip", "ip_address", "client_ip"
    ])

    error_col = find_column(df, [
        "not_found_404", "error_404_count",
        "404_count", "count_404", "http_404"
    ])

    if ip_col is None or error_col is None:
        no_data_message(
            "404 analysis",
            f"404/IP columns not found. Found: {list(df.columns)}"
        )
        return

    data = df.copy()
    data[ip_col] = clean_label(data[ip_col])
    data[error_col] = clean_numeric(data[error_col])
    data = data.nlargest(TOP_N, error_col).sort_values(error_col)

    plt.figure(figsize=(13, max(6, len(data) * 0.42)))

    plt.barh(
        data[ip_col],
        data[error_col],
        edgecolor="black",
        linewidth=0.3
    )

    plt.title("Top Client IPs by HTTP 404 Errors")
    plt.xlabel("Number of 404 Responses")
    plt.ylabel("Client IP")

    save_chart("04_top_404_errors.png")


# ============================================================
# CHART 5: IP BEHAVIOR COMPARISON
# ============================================================

def plot_ip_behavior(df):
    if df.empty:
        no_data_message("IP behavior", "No IP profile data.")
        return

    ip_col = find_column(df, [
        "host", "ip", "ip_address", "client_ip"
    ])

    request_col = find_column(df, [
        "total_requests", "request_count", "requests"
    ])

    error_col = find_column(df, [
        "not_found_404", "error_404_count",
        "404_count", "count_404"
    ])

    if ip_col is None or request_col is None or error_col is None:
        no_data_message(
            "IP behavior",
            f"Required columns missing. Found: {list(df.columns)}"
        )
        return

    data = df.copy()
    data[ip_col] = clean_label(data[ip_col])
    data[request_col] = clean_numeric(data[request_col])
    data[error_col] = clean_numeric(data[error_col])

    data = data.nlargest(TOP_N, request_col)

    plt.figure(figsize=(12, 8))

    plt.scatter(
        data[request_col],
        data[error_col],
        s=70,
        alpha=0.7,
        edgecolors="black",
        linewidths=0.4
    )

    for _, row in data.iterrows():
        plt.annotate(
            row[ip_col],
            (row[request_col], row[error_col]),
            xytext=(5, 5),
            textcoords="offset points",
            fontsize=8
        )

    plt.title("Client Behavior: Request Volume vs. 404 Errors")
    plt.xlabel("Total Requests")
    plt.ylabel("404 Errors")
    plt.grid(True, alpha=0.25)

    save_chart("05_ip_behavior_scatter.png")


# ============================================================
# CHART 6: REQUEST VOLUME DISTRIBUTION
# ============================================================

def plot_request_distribution(df):
    if df.empty:
        no_data_message("Request distribution", "No IP profile data.")
        return

    request_col = find_column(df, [
        "total_requests", "request_count", "requests"
    ])

    if request_col is None:
        no_data_message(
            "Request distribution",
            "Request count column not found."
        )
        return

    values = clean_numeric(df[request_col])
    values = values[values > 0]

    if values.empty:
        no_data_message("Request distribution", "No positive request counts.")
        return

    plt.figure(figsize=(12, 7))

    plt.hist(
        values,
        bins=40,
        edgecolor="black",
        linewidth=0.5
    )

    plt.title("Distribution of Requests Across Client IPs")
    plt.xlabel("Total Requests per IP")
    plt.ylabel("Number of IPs")
    plt.grid(True, alpha=0.2)

    save_chart("06_request_distribution.png")


# ============================================================
# CHART 7: HTTP STATUS CODE DISTRIBUTION
# ============================================================

STATUS_CATEGORY_COLORS = {
    "2xx Success": "#2ca02c",
    "3xx Redirect": "#1f77b4",
    "4xx Client Error": "#ff7f0e",
    "5xx Server Error": "#d62728",
    "Other": "#7f7f7f",
}


def plot_status_distribution(df):
    if df.empty:
        no_data_message("Status distribution", "No status distribution data.")
        return

    status_col = find_column(df, ["status", "status_code", "http_status"])
    category_col = find_column(df, ["status_category", "category"])
    total_col = find_column(df, ["total", "count", "request_count"])

    if status_col is None or total_col is None:
        no_data_message(
            "Status distribution",
            f"Required columns missing. Found: {list(df.columns)}"
        )
        return

    data = df.copy()
    data[total_col] = clean_numeric(data[total_col])
    data = data.sort_values(total_col, ascending=False)

    labels = data[status_col].astype(str)
    if category_col is not None:
        colors = [
            STATUS_CATEGORY_COLORS.get(cat, "#7f7f7f")
            for cat in data[category_col]
        ]
    else:
        colors = "#1f77b4"

    plt.figure(figsize=(12, max(5, len(data) * 0.4)))
    bars = plt.barh(labels, data[total_col], color=colors, edgecolor="black", linewidth=0.3)
    plt.gca().invert_yaxis()
    plt.xscale("log")
    plt.title("HTTP Status Code Distribution (log scale)")
    plt.xlabel("Number of Requests")
    plt.ylabel("HTTP Status Code")

    for bar, value in zip(bars, data[total_col]):
        plt.text(
            bar.get_width(),
            bar.get_y() + bar.get_height() / 2,
            f" {value:,.0f}",
            va="center",
            fontsize=9,
        )

    if category_col is not None:
        handles = [
            plt.Rectangle((0, 0), 1, 1, color=color)
            for color in STATUS_CATEGORY_COLORS.values()
        ]
        plt.legend(
            handles, STATUS_CATEGORY_COLORS.keys(),
            title="Category", loc="lower right", fontsize=8
        )

    save_chart("07_status_distribution.png")


# ============================================================
# SUMMARY REPORT
# ============================================================

def generate_summary(suspicious, per_minute, profiles, data_quality=None):
    summary_path = VISUALIZATION_DIR / "summary_report.txt"

    lines = [
        "WEBLOG INTRUSION ANALYSIS",
        "=" * 55,
        "",
    ]

    if data_quality is not None and not data_quality.empty:
        row = data_quality.iloc[0]

        def q(name, default=0):
            return int(row[name]) if name in row and pd.notna(row[name]) else default

        total = q("total")
        valid = q("valid")
        invalid = q("invalid")
        duplicates = q("duplicates")
        missing_ips = q("missing_ips")

        lines.extend([
            "DATA QUALITY",
            "-" * 55,
            f"Total raw log lines:       {total:,}",
            f"Valid, analyzed records:   {valid:,}",
            f"Invalid / unparsable:      {invalid:,} "
            f"({(invalid / total * 100) if total else 0:.2f}% of total)",
            f"  - unparsable (no host):  {missing_ips:,}",
            f"Exact duplicate lines:     {duplicates:,} "
            "(counted here, NOT removed from the analysis below)",
            "",
        ])

    lines.extend([
        "VISUALIZATION SUMMARY",
        "-" * 55,
        f"Suspicious IP records: {len(suspicious):,}",
        f"IP profile records: {len(profiles):,}",
        f"Request-window records: {len(per_minute):,}",
        "",
    ])

    if not profiles.empty:
        ip_col = find_column(profiles, [
            "host", "ip", "ip_address", "client_ip"
        ])
        req_col = find_column(profiles, [
            "total_requests", "request_count", "requests"
        ])

        if ip_col and req_col:
            data = profiles.copy()
            data[req_col] = clean_numeric(data[req_col])
            top = data.nlargest(5, req_col)

            lines.append("TOP 5 CLIENTS BY REQUEST VOLUME")
            lines.append("-" * 55)

            for _, row in top.iterrows():
                lines.append(
                    f"{row[ip_col]}: {row[req_col]:,.0f} requests"
                )

            lines.append("")

        error_col = find_column(profiles, [
            "not_found_404", "error_404_count",
            "404_count", "count_404"
        ])

        if ip_col and error_col:
            data = profiles.copy()
            data[error_col] = clean_numeric(data[error_col])
            top = data.nlargest(5, error_col)

            lines.append("TOP 5 CLIENTS BY 404 ERRORS")
            lines.append("-" * 55)

            for _, row in top.iterrows():
                lines.append(
                    f"{row[ip_col]}: {row[error_col]:,.0f} errors"
                )

            lines.append("")

    if not per_minute.empty:
        count_col = find_column(per_minute, [
            "requests_per_minute", "request_count",
            "requests", "count", "total_requests"
        ])

        if count_col:
            values = clean_numeric(per_minute[count_col])

            lines.extend([
                "REQUEST WINDOW STATISTICS",
                "-" * 55,
                f"Total window records: {len(per_minute):,}",
                f"Maximum requests in a window: {values.max():,.0f}",
                f"Average requests per window: {values.mean():,.2f}",
                "",
            ])

    lines.extend([
        "NOTES",
        "-" * 55,
        "These charts visualize the available Spark analysis outputs.",
        "A suspicious IP is a candidate for investigation, not proof",
        "of malicious activity.",
        "",
    ])

    summary_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[SAVED] {summary_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    print("\n" + "=" * 65)
    print("WEBLOG INTRUSION ANALYSIS - VISUALIZATION")
    print("=" * 65)

    suspicious = read_spark_csv(SUSPICIOUS_DIR)
    per_minute = read_spark_csv(
        REPORT_DIR / "requests_per_minute"
    )
    profiles = read_spark_csv(
        REPORT_DIR / "ip_behavior_profile"
    )
    status_distribution = read_spark_csv(
        REPORT_DIR / "status_distribution"
    )
    data_quality = read_spark_csv(
        REPORT_DIR / "data_quality"
    )

    if suspicious.empty and per_minute.empty and profiles.empty:
        print("\n[ERROR] No report data was found.")
        print("Check that Spark analysis has completed successfully.")
        return

    print("\nGenerating charts...\n")

    plot_suspicious_ips(suspicious)
    plot_requests_per_minute(per_minute)
    plot_top_ip_volume(profiles)
    plot_404_analysis(profiles)
    plot_ip_behavior(profiles)
    plot_request_distribution(profiles)
    plot_status_distribution(status_distribution)

    generate_summary(suspicious, per_minute, profiles, data_quality)

    print("\n" + "=" * 65)
    print("VISUALIZATION COMPLETE")
    print("=" * 65)
    print(f"Output directory: {VISUALIZATION_DIR}")
    print("\nGenerated files:")

    for file in sorted(VISUALIZATION_DIR.glob("*")):
        if file.is_file():
            print(f"  - {file.name}")

    print("\nOpen the PNG files to view the charts.")


if __name__ == "__main__":
    main()