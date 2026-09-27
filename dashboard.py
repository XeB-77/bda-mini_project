
import re
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================
# Performance improvements:
# - IP filter choices use compact per-IP reports, not minute-level rows.
# - Traffic charts aggregate to 15-minute buckets.
# - Large tables and CSV exports are capped for responsiveness.

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
SUSPICIOUS_DIR = OUTPUT_DIR / "suspicious_ips"
REPORT_DIR = OUTPUT_DIR / "reports"

st.set_page_config(
    page_title="Weblog Intrusion Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------
# DESIGN SYSTEM
# ------------------------------------------------------------
# Dark cybersecurity-analytics theme: charcoal/navy surfaces, a single
# teal accent, and one consistent color mapping for severity / HTTP
# status categories used everywhere in the app (metrics, charts, tables).

COLORS = {
    "bg": "#0b1220",
    "surface": "#111a2c",
    "surface_alt": "#0e1626",
    "border": "rgba(148, 178, 214, 0.14)",
    "text": "#e6edf7",
    "text_muted": "#8fa1bd",
    "accent": "#2dd4bf",
    "accent_dim": "rgba(45, 212, 191, 0.15)",
    "blue": "#38bdf8",
    "success": "#34d399",
    "warning": "#fbbf24",
    "danger": "#f87171",
}

STATUS_COLORS = {
    "2xx Success": COLORS["success"],
    "3xx Redirect": COLORS["blue"],
    "4xx Client Error": COLORS["warning"],
    "5xx Server Error": COLORS["danger"],
    "Other": COLORS["text_muted"],
}

REASON_COLORS = {
    "High request burst": COLORS["danger"],
    "High number of 404 errors": COLORS["warning"],
    "High number of unique URLs": COLORS["blue"],
}

PLOTLY_TEMPLATE = go.layout.Template(
    layout=go.Layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLORS["text"], size=13),
        title=dict(font=dict(color=COLORS["text"], size=16)),
        xaxis=dict(
            gridcolor="rgba(148, 178, 214, 0.10)",
            linecolor=COLORS["border"],
            zerolinecolor="rgba(148, 178, 214, 0.10)",
        ),
        yaxis=dict(
            gridcolor="rgba(148, 178, 214, 0.10)",
            linecolor=COLORS["border"],
            zerolinecolor="rgba(148, 178, 214, 0.10)",
        ),
        colorway=[
            COLORS["accent"], COLORS["blue"], COLORS["warning"],
            COLORS["danger"], "#a78bfa", "#f472b6", "#facc15",
        ],
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        margin=dict(t=60, l=10, r=10, b=10),
    )
)
pio.templates["weblog_dark"] = PLOTLY_TEMPLATE
pio.templates.default = "weblog_dark"

st.markdown(
    f"""
    <style>
    .stApp {{
        background: {COLORS["bg"]};
        color: {COLORS["text"]};
    }}
    .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }}
    section[data-testid="stSidebar"] {{
        background: {COLORS["surface_alt"]};
        border-right: 1px solid {COLORS["border"]};
    }}
    h1, h2, h3, h4 {{
        color: {COLORS["text"]} !important;
        letter-spacing: -0.01em;
    }}
    p, span, label, .stMarkdown {{
        color: {COLORS["text"]};
    }}
    div[data-testid="stMetric"] {{
        background: linear-gradient(180deg, {COLORS["surface"]} 0%, {COLORS["surface_alt"]} 100%);
        border: 1px solid {COLORS["border"]};
        padding: 18px 20px;
        border-radius: 14px;
        box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset;
    }}
    div[data-testid="stMetricLabel"] {{
        color: {COLORS["text_muted"]} !important;
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }}
    div[data-testid="stMetricValue"] {{
        color: {COLORS["text"]} !important;
        font-weight: 600;
    }}
    div[data-testid="stDataFrame"] {{
        border: 1px solid {COLORS["border"]};
        border-radius: 10px;
        overflow: hidden;
    }}
    .stButton button, .stDownloadButton button {{
        background: {COLORS["accent_dim"]};
        color: {COLORS["accent"]};
        border: 1px solid rgba(45, 212, 191, 0.35);
        border-radius: 8px;
        font-weight: 500;
    }}
    .stButton button:hover, .stDownloadButton button:hover {{
        background: rgba(45, 212, 191, 0.28);
        color: {COLORS["accent"]};
        border-color: {COLORS["accent"]};
    }}
    div[data-baseweb="radio"] label {{
        color: {COLORS["text"]};
    }}
    hr, div[data-testid="stDivider"] {{
        border-color: {COLORS["border"]} !important;
    }}
    .caption-muted {{
        color: {COLORS["text_muted"]};
        font-size: 0.85rem;
    }}
    .badge {{
        display: inline-block;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.02em;
        margin-right: 6px;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


def badge(text, color):
    return (
        f'<span class="badge" style="background:{color}22;'
        f'color:{color};border:1px solid {color}55;">{text}</span>'
    )


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data(show_spinner="Loading Spark reports...")
def load_spark_csv(folder_path):
    """Load CSV part files from a Spark output directory."""
    folder = Path(folder_path)

    if not folder.exists():
        return pd.DataFrame()

    if folder.is_file() and folder.suffix.lower() == ".csv":
        files = [folder]
    else:
        files = sorted(folder.rglob("part-*.csv"))

    if not files:
        return pd.DataFrame()

    frames = []

    for file in files:
        try:
            frame = pd.read_csv(file)
            if not frame.empty:
                frames.append(frame)
        except Exception:
            continue

    if not frames:
        return pd.DataFrame()

    df = pd.concat(frames, ignore_index=True)
    df.columns = [str(c).strip() for c in df.columns]

    return df


def normalize_column(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def find_column(df, candidates):
    if df.empty:
        return None

    columns = {
        normalize_column(c): c
        for c in df.columns
    }

    for candidate in candidates:
        key = normalize_column(candidate)
        if key in columns:
            return columns[key]

    return None


def numeric(series):
    return pd.to_numeric(series, errors="coerce").fillna(0)


def format_number(value):
    return f"{value:,.0f}"



@st.cache_data(show_spinner=False)
def cached_csv(dataframe, max_rows=50000):
    """Cache CSV serialization and cap large dashboard exports."""
    return dataframe.head(max_rows).to_csv(index=False).encode("utf-8")


@st.cache_data(show_spinner="Preparing report data...")
def prepare_data(suspicious, profiles, windows, status_dist, method_dist):
    suspicious = suspicious.copy()
    profiles = profiles.copy()
    windows = windows.copy()
    status_dist = status_dist.copy()
    method_dist = method_dist.copy()

    for df in (suspicious, profiles):
        for column in [
            "total_requests",
            "error_404_count",
            "error_count",
            "unique_urls",
            "avg_response_bytes",
            "error_rate_pct",
        ]:
            if column in df.columns:
                df[column] = numeric(df[column])

    if "requests_per_minute" in windows.columns:
        windows["requests_per_minute"] = numeric(
            windows["requests_per_minute"]
        )

    if "window_start" in windows.columns:
        windows["window_start"] = pd.to_datetime(
            windows["window_start"], errors="coerce"
        )

    if "window_end" in windows.columns:
        windows["window_end"] = pd.to_datetime(
            windows["window_end"], errors="coerce"
        )

    if "total" in status_dist.columns:
        status_dist["total"] = numeric(status_dist["total"])

    if "total" in method_dist.columns:
        method_dist["total"] = numeric(method_dist["total"])

    return suspicious, profiles, windows, status_dist, method_dist


@st.cache_data(show_spinner=False)
def load_data_quality():
    """
    Load the single-row data-quality summary written by spark_analysis.py.
    Returns a plain dict with sane zero defaults so the rest of the app
    doesn't need to special-case a missing report.
    """
    df = load_spark_csv(str(REPORT_DIR / "data_quality"))
    fields = [
        "total", "valid", "invalid", "duplicates",
        "missing_ips", "bad_status", "bad_timestamp", "bad_bytes",
    ]
    if df.empty:
        return {field: 0 for field in fields}, False

    row = df.iloc[0]
    result = {}
    for field in fields:
        result[field] = int(numeric(pd.Series([row.get(field, 0)])).iloc[0])
    return result, True


# ============================================================
# LOAD REPORTS
# ============================================================

suspicious_raw = load_spark_csv(str(SUSPICIOUS_DIR))
profiles_raw = load_spark_csv(
    str(REPORT_DIR / "ip_behavior_profile")
)
windows_raw = load_spark_csv(
    str(REPORT_DIR / "requests_per_minute")
)
status_dist_raw = load_spark_csv(
    str(REPORT_DIR / "status_distribution")
)
method_dist_raw = load_spark_csv(
    str(REPORT_DIR / "method_distribution")
)

suspicious, profiles, windows, status_dist, method_dist = prepare_data(
    suspicious_raw,
    profiles_raw,
    windows_raw,
    status_dist_raw,
    method_dist_raw,
)

data_quality, data_quality_available = load_data_quality()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ Weblog Security")
st.sidebar.caption("Big Data Analytics Project")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Traffic Analysis",
        "Suspicious IPs",
        "IP Behavior",
        "HTTP Errors",
        "Data Explorer",
    ],
)

st.sidebar.divider()

if st.sidebar.button("🔄 Refresh reports", width="stretch"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.caption(
    "Data source: Spark CSV reports"
)


# ============================================================
# COMMON FILTERS
# ============================================================

all_ips = set()

for df in (suspicious, profiles):
    if "host" in df.columns:
        all_ips.update(
            df["host"].dropna().astype(str).unique().tolist()
        )

all_ips = sorted(all_ips)

selected_ips = st.sidebar.multiselect(
    "Filter by IP address",
    options=all_ips,
    default=[],
    help="Leave empty to include all IP addresses.",
)

if selected_ips:
    if "host" in suspicious.columns:
        suspicious = suspicious[
            suspicious["host"].astype(str).isin(selected_ips)
        ]

    if "host" in profiles.columns:
        profiles = profiles[
            profiles["host"].astype(str).isin(selected_ips)
        ]

    if "host" in windows.columns:
        windows = windows[
            windows["host"].astype(str).isin(selected_ips)
        ]


# ============================================================
# GLOBAL METRICS
# ============================================================

total_requests = (
    profiles["total_requests"].sum()
    if "total_requests" in profiles.columns
    else 0
)

total_404 = (
    profiles["error_404_count"].sum()
    if "error_404_count" in profiles.columns
    else 0
)

total_errors = (
    profiles["error_count"].sum()
    if "error_count" in profiles.columns
    else 0
)

total_ips = (
    profiles["host"].nunique()
    if "host" in profiles.columns
    else len(profiles)
)

suspicious_count = (
    suspicious["host"].nunique()
    if "host" in suspicious.columns
    else len(suspicious)
)

avg_error_rate = (
    profiles["error_rate_pct"].mean()
    if "error_rate_pct" in profiles.columns and not profiles.empty
    else 0
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Weblog Intrusion Analysis Dashboard")

st.markdown(
    """
    Interactive analysis of NASA-HTTP web server access logs using
    **PySpark, Spark SQL, and Streamlit**.
    """
)

st.caption(
    "Suspicious IPs are heuristic candidates for investigation, "
    "not proof of malicious activity. See the Suspicious IPs page "
    "for the detection rules used."
)

st.divider()


# ============================================================
# PAGE 1: OVERVIEW
# ============================================================

if page == "Overview":

    st.subheader("📊 System Overview")

    if not windows.empty and "window_start" in windows.columns:
        valid_period = windows["window_start"].dropna()
        if not valid_period.empty:
            period_start = valid_period.min()
            period_end = valid_period.max()
            st.markdown(
                f'<span class="caption-muted">Dataset: NASA-HTTP access logs '
                f'(Kennedy Space Center WWW server) &nbsp;·&nbsp; '
                f'Analysis period: {period_start:%Y-%m-%d} to '
                f'{period_end:%Y-%m-%d} (UTC)</span>',
                unsafe_allow_html=True,
            )
            st.write("")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Requests",
        format_number(total_requests),
    )

    col2.metric(
        "Unique IPs",
        format_number(total_ips),
    )

    col3.metric(
        "Suspicious IPs",
        format_number(suspicious_count),
    )

    col4.metric(
        "404 Errors",
        format_number(total_404),
    )

    st.divider()

    st.subheader("🧪 Data Quality")

    if data_quality_available:
        dq = data_quality
        invalid_pct = (
            dq["invalid"] / dq["total"] * 100 if dq["total"] else 0
        )

        dq1, dq2, dq3, dq4 = st.columns(4)
        dq1.metric("Total Raw Log Lines", format_number(dq["total"]))
        dq2.metric(
            "Valid Records",
            format_number(dq["valid"]),
            help="Matched the log pattern and had a castable status, "
            "timestamp, and byte count. This is the record set every "
            "other page in this dashboard is built from.",
        )
        dq3.metric(
            "Invalid / Unparsable",
            f"{format_number(dq['invalid'])} ({invalid_pct:.2f}%)",
            help="Lines that failed to parse, mostly requests missing "
            "the HTTP protocol token entirely.",
        )
        dq4.metric(
            "Exact Duplicate Lines",
            format_number(dq["duplicates"]),
            help="Byte-for-byte repeated raw log lines. Measured but "
            "NOT removed from any analysis on this dashboard.",
        )

        st.markdown(
            f'<span class="caption-muted">'
            f'Of the {format_number(dq["invalid"])} invalid records, '
            f'{format_number(dq["missing_ips"])} could not be parsed at all '
            f'(no HTTP protocol token or other malformed structure). '
            f'Duplicate lines are counted above for transparency but are '
            f'intentionally left in the analysis — they make up a negligible '
            f'share of the dataset and removing them would silently change '
            f'historical totals.</span>',
            unsafe_allow_html=True,
        )
    else:
        st.info(
            "The data_quality report was not found. Run spark_analysis.py "
            "to generate it — the dashboard falls back to totals derived "
            "from the IP behavior profile in the meantime."
        )

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Top IPs by Request Volume")

        if not profiles.empty and "total_requests" in profiles.columns:
            top = profiles.nlargest(10, "total_requests").sort_values(
                "total_requests"
            )

            fig = px.bar(
                top,
                x="total_requests",
                y="host",
                orientation="h",
                title="Top 10 Client IPs",
                labels={
                    "total_requests": "Total Requests",
                    "host": "Client IP",
                },
                color_discrete_sequence=[COLORS["accent"]],
            )

            fig.update_layout(height=450, showlegend=False)

            st.plotly_chart(fig, width="stretch")

        else:
            st.info("IP profile data is unavailable.")

    with right:
        st.subheader("HTTP Status Code Mix")

        if not status_dist.empty and "total" in status_dist.columns:
            category_col = find_column(status_dist, ["status_category", "category"])

            if category_col:
                by_category = (
                    status_dist.groupby(category_col, as_index=False)["total"]
                    .sum()
                    .sort_values("total", ascending=False)
                )

                fig = px.pie(
                    by_category,
                    names=category_col,
                    values="total",
                    title="Requests by Status Category",
                    color=category_col,
                    color_discrete_map=STATUS_COLORS,
                    hole=0.55,
                )

                fig.update_layout(height=450)
                fig.update_traces(textinfo="percent+label")

                st.plotly_chart(fig, width="stretch")
            else:
                st.info("Status category column not found.")
        else:
            st.info(
                "Status distribution data is unavailable. Run "
                "spark_analysis.py to generate output/reports/status_distribution."
            )

    st.divider()

    st.subheader("🚨 Suspicious IP Preview")

    if not suspicious.empty:
        display_columns = [
            column
            for column in [
                "host",
                "total_requests",
                "error_404_count",
                "error_count",
                "unique_urls",
                "error_rate_pct",
                "reason",
            ]
            if column in suspicious.columns
        ]

        st.dataframe(
            suspicious[display_columns].head(15),
            width="stretch",
            hide_index=True,
        )

    else:
        st.success("No suspicious IP records in the current selection.")


# ============================================================
# PAGE 2: TRAFFIC ANALYSIS
# ============================================================

elif page == "Traffic Analysis":

    st.subheader("📈 Traffic Analysis")

    if windows.empty:
        st.warning("Request-window data is unavailable.")

    else:
        valid_windows = windows.dropna(
            subset=["window_start"]
        ).copy()

        if valid_windows.empty:
            st.warning("No valid timestamps were found.")

        else:
            min_time = valid_windows["window_start"].min()
            max_time = valid_windows["window_start"].max()

            date_range = st.date_input(
                "Select traffic date range",
                value=(min_time.date(), max_time.date()),
                min_value=min_time.date(),
                max_value=max_time.date(),
            )

            if isinstance(date_range, tuple) and len(date_range) == 2:
                start_date, end_date = date_range

                valid_windows = valid_windows[
                    (valid_windows["window_start"].dt.date >= start_date)
                    & (valid_windows["window_start"].dt.date <= end_date)
                ]

            st.metric(
                "Request-window records",
                format_number(len(valid_windows)),
            )

            if not valid_windows.empty:
                st.markdown("### Request Volume Over Time")

                top_ips = (
                    valid_windows.groupby("host")["requests_per_minute"]
                    .sum()
                    .nlargest(10)
                    .index.tolist()
                )

                chart_data = valid_windows[
                    valid_windows["host"].isin(top_ips)
                ].copy()

                # Aggregate minute-level records into 15-minute buckets.
                chart_data["time_bucket"] = chart_data["window_start"].dt.floor("15min")
                chart_data = (
                    chart_data.groupby(["host", "time_bucket"], as_index=False)
                    ["requests_per_minute"].sum()
                    .rename(columns={"time_bucket": "window_start"})
                )

                fig = px.line(
                    chart_data,
                    x="window_start",
                    y="requests_per_minute",
                    color="host",
                    title="Requests per Minute by Client",
                    labels={
                        "window_start": "Time",
                        "requests_per_minute": "Requests per Minute",
                        "host": "Client IP",
                    },
                )

                fig.update_layout(
                    height=550,
                    hovermode="x unified",
                )

                st.plotly_chart(fig, width="stretch")

                st.markdown("### Peak Request Windows")

                peak = valid_windows.nlargest(
                    20, "requests_per_minute"
                )

                st.dataframe(
                    peak[
                        [
                            c for c in [
                                "host",
                                "window_start",
                                "window_end",
                                "requests_per_minute",
                            ]
                            if c in peak.columns
                        ]
                    ],
                    width="stretch",
                    hide_index=True,
                )

                st.download_button(
                    "⬇️ Download filtered traffic CSV",
                    data=cached_csv(valid_windows, 50000),
                    file_name="filtered_traffic.csv",
                    mime="text/csv",
                )


# ============================================================
# PAGE 3: SUSPICIOUS IPS
# ============================================================

elif page == "Suspicious IPs":

    st.subheader("🚨 Suspicious IP Investigation")

    with st.expander("How are these flagged? (heuristic rules)", expanded=False):
        st.markdown(
            f"""
An IP is flagged as a **candidate for investigation** — not confirmed
malicious — if it trips any one of these rules:

{badge("High request burst", REASON_COLORS["High request burst"])}
60+ requests from the same host within a single 1-minute window.

{badge("High 404 errors", REASON_COLORS["High number of 404 errors"])}
20 or more HTTP 404 responses.

{badge("High unique URLs", REASON_COLORS["High number of unique URLs"])}
100 or more distinct URLs requested (often consistent with scanning).

**Known limitation:** shared infrastructure — corporate proxies, or
1995-era AOL/Prodigy dial-up gateways fronting many real users behind
one hostname — can trip these same thresholds legitimately. Several of
the highest-volume hosts in this dataset are exactly that. Treat every
row below as a lead to check, not a verdict.
            """,
            unsafe_allow_html=True,
        )

    if suspicious.empty:
        st.success("No suspicious IP records found in this selection.")

    else:
        st.metric(
            "Suspicious IP records",
            format_number(len(suspicious)),
        )

        search = st.text_input(
            "Search suspicious IPs",
            placeholder="Enter an IP address or hostname...",
        )

        filtered = suspicious.copy()

        if search:
            filtered = filtered[
                filtered["host"].astype(str).str.contains(
                    search,
                    case=False,
                    na=False,
                )
            ]

        display_columns = [
            c for c in [
                "host",
                "total_requests",
                "error_404_count",
                "error_count",
                "unique_urls",
                "avg_response_bytes",
                "error_rate_pct",
                "high_request_burst",
                "suspicious",
                "reason",
            ]
            if c in filtered.columns
        ]

        st.dataframe(
            filtered[display_columns],
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "⬇️ Download suspicious IPs",
            data=cached_csv(filtered, 50000),
            file_name="suspicious_ips.csv",
            mime="text/csv",
        )

        if "reason" in filtered.columns:
            st.markdown("### Detection Reasons")

            reasons = (
                filtered["reason"]
                .fillna("Not specified")
                .value_counts()
                .reset_index()
            )

            reasons.columns = ["reason", "count"]

            fig = px.bar(
                reasons,
                x="count",
                y="reason",
                orientation="h",
                title="Suspicious IP Detection Reasons",
                labels={
                    "count": "Number of IPs",
                    "reason": "Detection Reason",
                },
                color="reason",
                color_discrete_map=REASON_COLORS,
            )

            fig.update_layout(height=450, showlegend=False)

            st.plotly_chart(fig, width="stretch")


# ============================================================
# PAGE 4: IP BEHAVIOR
# ============================================================

elif page == "IP Behavior":

    st.subheader("🔍 IP Behavior Analysis")

    if profiles.empty:
        st.warning("IP behavior profiles are unavailable.")

    else:
        col1, col2, col3 = st.columns(3)

        col1.metric("Unique IPs", format_number(total_ips))
        col2.metric("Total Requests", format_number(total_requests))
        col3.metric("Average Error Rate", f"{avg_error_rate:.2f}%")

        st.divider()

        st.markdown("### Request Volume vs. Error Count")

        if (
            "total_requests" in profiles.columns
            and "error_count" in profiles.columns
        ):
            fig = px.scatter(
                profiles,
                x="total_requests",
                y="error_count",
                hover_name="host",
                color="error_rate_pct" if "error_rate_pct" in profiles.columns else None,
                size="unique_urls" if "unique_urls" in profiles.columns else None,
                title="Client Request Volume and Error Patterns",
                labels={
                    "total_requests": "Total Requests",
                    "error_count": "Total Errors",
                    "error_rate_pct": "Error Rate (%)",
                    "unique_urls": "Unique URLs",
                },
            )

            fig.update_layout(height=600)

            st.plotly_chart(fig, width="stretch")

        st.markdown("### Error Rate Distribution")

        if "error_rate_pct" in profiles.columns:
            fig = px.histogram(
                profiles,
                x="error_rate_pct",
                nbins=40,
                title="Distribution of Error Rates Across IPs",
                labels={
                    "error_rate_pct": "Error Rate (%)",
                    "count": "Number of IPs",
                },
            )

            fig.update_layout(height=450)

            st.plotly_chart(fig, width="stretch")

        st.markdown("### IP Behavior Table")

        st.dataframe(
            (profiles.sort_values(
                "total_requests", ascending=False
            ) if "total_requests" in profiles.columns else profiles).head(2000),
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "⬇️ Download IP behavior profiles",
            data=cached_csv(profiles, 50000),
            file_name="ip_behavior_profiles.csv",
            mime="text/csv",
        )


# ============================================================
# PAGE 5: HTTP ERRORS
# ============================================================

elif page == "HTTP Errors":

    st.subheader("🌐 HTTP Error Analysis")

    if profiles.empty:
        st.warning("IP behavior data is unavailable.")

    else:
        other_errors = max(total_errors - total_404, 0)

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("404 Responses", format_number(total_404))

        with col2:
            st.metric(
                "Other 4xx/5xx Errors",
                format_number(other_errors),
                help="Error responses (status >= 400) excluding 404. "
                "Not additive with the total below — 404s are a subset "
                "of total errors.",
            )

        with col3:
            st.metric(
                "Total 4xx/5xx Errors",
                format_number(total_errors),
                help="All responses with status >= 400, including 404.",
            )

        st.divider()

        if not status_dist.empty and "status" in status_dist.columns:
            st.markdown("### Status Code Breakdown")

            category_col = find_column(
                status_dist, ["status_category", "category"]
            )

            left, right = st.columns([3, 2])

            with left:
                display_dist = status_dist.sort_values(
                    "total", ascending=False
                )

                fig = px.bar(
                    display_dist,
                    x="status",
                    y="total",
                    color=category_col if category_col else None,
                    color_discrete_map=STATUS_COLORS if category_col else None,
                    title="Requests by HTTP Status Code",
                    labels={"status": "HTTP Status Code", "total": "Requests"},
                    log_y=True,
                )
                fig.update_xaxes(type="category")
                fig.update_layout(height=420)

                st.plotly_chart(fig, width="stretch")

            with right:
                if category_col:
                    error_only = status_dist[
                        status_dist[category_col].isin(
                            ["4xx Client Error", "5xx Server Error"]
                        )
                    ]

                    if not error_only.empty:
                        by_cat = (
                            error_only.groupby(category_col, as_index=False)[
                                "total"
                            ].sum()
                        )

                        fig = px.pie(
                            by_cat,
                            names=category_col,
                            values="total",
                            title="4xx vs 5xx Split",
                            color=category_col,
                            color_discrete_map=STATUS_COLORS,
                            hole=0.5,
                        )
                        fig.update_layout(height=420)
                        st.plotly_chart(fig, width="stretch")
                    else:
                        st.info("No 4xx/5xx records in this selection.")
        else:
            st.info(
                "Status distribution data is unavailable. Run "
                "spark_analysis.py to generate "
                "output/reports/status_distribution."
            )

        st.divider()

        if "error_404_count" in profiles.columns:
            st.markdown("### Top Clients by 404 Errors")

            top = profiles.nlargest(
                20, "error_404_count"
            ).sort_values("error_404_count")

            fig = px.bar(
                top,
                x="error_404_count",
                y="host",
                orientation="h",
                title="Top 20 Clients by HTTP 404 Errors",
                labels={
                    "error_404_count": "404 Responses",
                    "host": "Client IP",
                },
                color_discrete_sequence=[COLORS["warning"]],
            )

            fig.update_layout(height=600)

            st.plotly_chart(fig, width="stretch")

        else:
            st.info("The 404 error count is not available.")

        st.markdown("### Error Rate vs. Request Volume")

        if (
            "error_rate_pct" in profiles.columns
            and "total_requests" in profiles.columns
        ):
            fig = px.scatter(
                profiles,
                x="total_requests",
                y="error_rate_pct",
                hover_name="host",
                title="Client Error Rate vs. Request Volume",
                labels={
                    "total_requests": "Total Requests",
                    "error_rate_pct": "Error Rate (%)",
                },
                color_discrete_sequence=[COLORS["blue"]],
            )

            fig.update_layout(height=500)

            st.plotly_chart(fig, width="stretch")


# ============================================================
# PAGE 6: DATA EXPLORER
# ============================================================

elif page == "Data Explorer":

    st.subheader("🗂️ Data Explorer")

    dataset_name = st.selectbox(
        "Select a dataset",
        [
            "Suspicious IPs",
            "IP Behavior Profiles",
            "Requests per Minute",
            "HTTP Status Distribution",
            "HTTP Method Distribution",
        ],
    )

    datasets = {
        "Suspicious IPs": suspicious,
        "IP Behavior Profiles": profiles,
        "Requests per Minute": windows,
        "HTTP Status Distribution": status_dist,
        "HTTP Method Distribution": method_dist,
    }

    selected_df = datasets[dataset_name]

    if selected_df.empty:
        st.warning("This dataset is empty.")

    else:
        st.caption(
            f"{len(selected_df):,} rows · {len(selected_df.columns)} columns"
        )

        display_limit = st.select_slider(
            "Rows to display",
            options=[100, 500, 1000, 2000, 5000],
            value=1000,
        )
        st.dataframe(
            selected_df.head(display_limit),
            width="stretch",
            hide_index=True,
        )
        st.caption("The table is limited for responsiveness. CSV downloads are capped at 50,000 rows.")

        st.download_button(
            f"⬇️ Download {dataset_name} (up to 50,000 rows)",
            data=cached_csv(selected_df, 50000),
            file_name=f"{dataset_name.lower().replace(' ', '_')}.csv",
            mime="text/csv",
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Weblog Intrusion Analysis | Big Data Analytics Mini Project | "
    "PySpark + Streamlit + Plotly"
)