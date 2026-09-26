
import re
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    div[data-testid="stMetric"] {
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.2);
        padding: 16px;
        border-radius: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
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
def prepare_data(suspicious, profiles, windows):
    suspicious = suspicious.copy()
    profiles = profiles.copy()
    windows = windows.copy()

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

    return suspicious, profiles, windows


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

suspicious, profiles, windows = prepare_data(
    suspicious_raw,
    profiles_raw,
    windows_raw,
)


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
    Interactive analysis of web server access logs using
    **Apache Spark, PySpark, and Streamlit**.
    """
)

st.caption(
    "Suspicious IPs are candidates for investigation, "
    "not proof of malicious activity."
)

st.divider()


# ============================================================
# PAGE 1: OVERVIEW
# ============================================================

if page == "Overview":

    st.subheader("📊 System Overview")

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
                color="total_requests",
                color_continuous_scale="Blues",
            )

            fig.update_layout(
                height=450,
                showlegend=False,
            )

            st.plotly_chart(fig, width="stretch")

        else:
            st.info("IP profile data is unavailable.")

    with right:
        st.subheader("Top IPs by 404 Errors")

        if not profiles.empty and "error_404_count" in profiles.columns:
            top = profiles.nlargest(10, "error_404_count").sort_values(
                "error_404_count"
            )

            fig = px.bar(
                top,
                x="error_404_count",
                y="host",
                orientation="h",
                title="Top 10 Clients by 404 Errors",
                labels={
                    "error_404_count": "404 Errors",
                    "host": "Client IP",
                },
                color="error_404_count",
                color_continuous_scale="Reds",
            )

            fig.update_layout(height=450, showlegend=False)

            st.plotly_chart(fig, width="stretch")

        else:
            st.info("404 error data is unavailable.")

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

        if "suspicious" in filtered.columns:
            suspicious_only = filtered[
                filtered["suspicious"].astype(str).str.lower().isin(
                    ["true", "1", "yes"]
                )
            ]

            if not suspicious_only.empty:
                filtered = suspicious_only

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
            )

            fig.update_layout(height=450)

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
        col1, col2 = st.columns(2)

        with col1:
            st.metric("404 Responses", format_number(total_404))

        with col2:
            st.metric("Other Error Responses", format_number(total_errors))

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
                color="error_404_count",
                color_continuous_scale="Reds",
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
            )

            fig.update_layout(height=500)

            st.plotly_chart(fig, width="stretch")

        st.info(
            "The current IP profile reports contain aggregated error counts, "
            "not a complete HTTP status-code distribution. "
            "A status-code breakdown requires a separate Spark aggregation."
        )


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
        ],
    )

    datasets = {
        "Suspicious IPs": suspicious,
        "IP Behavior Profiles": profiles,
        "Requests per Minute": windows,
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