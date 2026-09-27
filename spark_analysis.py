"""
Spark analysis of the NASA weblog dataset.

Reads the ingested log files, parses each line into structured fields,
runs the traffic / error / suspicious-activity analysis, and writes
CSV reports to output/reports and output/suspicious_ips.

Query style: several aggregations below are expressed as genuine Spark SQL
(`spark.sql(...)`) against a registered temp view, which is what actually
runs in a Hive/HiveQL environment too — Spark SQL is HiveQL-compatible.
The remaining aggregations use the DataFrame API, which compiles to the
same Catalyst query plan as the equivalent SQL; they are used where a
window function or multi-stage join reads more clearly that way.
"""

import os

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    count,
    countDistinct,
    sum as spark_sum,
    when,
    to_timestamp,
    window,
    avg,
    round as spark_round,
    regexp_extract,
    trim,
    lit,
)

from log_patterns import (
    LOG_PATTERN,
    MIN_404_ERRORS,
    MIN_UNIQUE_URLS,
    MIN_REQUESTS_PER_MINUTE,
    REPORT_TIMEZONE,
)

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INGESTED_DIR = os.path.join(BASE_DIR, "data", "ingested")
OUTPUT_DIR = os.path.join(BASE_DIR, "output", "suspicious_ips")
REPORT_DIR = os.path.join(BASE_DIR, "output", "reports")


# ============================================================
# DATA QUALITY VALIDATION
# ============================================================

def validate_logs(raw, parsed, logs_df):
    """
    Generate data quality metrics for the weblog dataset.

    Definitions used throughout this report:
      - total:      every line read from the ingested log files, including
                     exact duplicate lines.
      - unparsable: lines that do not match LOG_PATTERN at all (host could
                     not be extracted) — counted from `parsed`, not from the
                     already-filtered `logs_df`, so this number can actually
                     be nonzero.
      - valid:      lines that matched LOG_PATTERN AND had a castable status
                     code, timestamp, and byte count.
      - invalid:    total - valid. This includes unparsable lines plus lines
                     that parsed but failed a field-level check.
      - duplicates: exact repeated raw lines (byte-for-byte). These are
                     measured but NOT removed from the analysis below —
                     removing them would silently change historical counts,
                     and at 0.04% of this dataset they do not materially
                     change any result. They are surfaced here so the
                     discrepancy is visible rather than hidden.
    """

    total = raw.count()
    valid = logs_df.count()
    invalid = total - valid

    duplicates = (
        raw.groupBy("value")
        .count()
        .filter(col("count") > 1)
        .agg(
            spark_sum(col("count") - 1).alias("duplicates")
        )
        .first()["duplicates"] or 0
    )

    # Computed on `parsed` (pre field-level filtering), not on `logs_df`,
    # so this reflects lines that genuinely failed to parse a host at all.
    missing_ips = parsed.filter(
        col("host").isNull() | (trim(col("host")) == "")
    ).count()

    # Field-level failure breakdown. These are NOT mutually exclusive —
    # a single malformed line can fail more than one check — so they will
    # not sum exactly to `invalid`.
    parsed_ok = parsed.filter(col("host") != "")
    bad_status = parsed_ok.filter(
        col("status_text").cast("int").isNull()
    ).count()
    bad_bytes = parsed_ok.filter(
        (col("bytes_text") != "-") & col("bytes_text").cast("long").isNull()
    ).count()
    bad_timestamp = parsed_ok.filter(
        to_timestamp(
            col("request_time"), "dd/MMM/yyyy:HH:mm:ss Z"
        ).isNull()
    ).count()

    print("\n" + "=" * 55)
    print("DATA QUALITY REPORT")
    print("=" * 55)
    print(f"Total records:            {total}")
    print(f"Valid records:            {valid}")
    print(f"Invalid records:          {invalid}")
    print(f"  - unparsable (no host): {missing_ips}")
    print(f"  - bad status code:      {bad_status}")
    print(f"  - bad timestamp:        {bad_timestamp}")
    print(f"  - bad byte count:       {bad_bytes}")
    print(f"Duplicate raw lines:      {duplicates} (kept in the analysis)")
    print("=" * 55)

    return {
        "total": total,
        "valid": valid,
        "invalid": invalid,
        "duplicates": duplicates,
        "missing_ips": missing_ips,
        "bad_status": bad_status,
        "bad_timestamp": bad_timestamp,
        "bad_bytes": bad_bytes,
    }


# ============================================================
# MAIN ANALYSIS
# ============================================================

def run():

    spark = (
        SparkSession.builder
        .appName("WeblogIntrusionAnalysis")
        .master("local[*]")
        .config("spark.sql.session.timeZone", REPORT_TIMEZONE)
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    try:
        # ----------------------------------------------------
        # 1. READ RAW LOGS
        # ----------------------------------------------------

        if not os.path.exists(INGESTED_DIR):
            raise FileNotFoundError(
                f"Ingested data directory not found: {INGESTED_DIR}"
            )

        raw = spark.read.text(INGESTED_DIR)

        # ----------------------------------------------------
        # 2. PARSE LOG FIELDS
        # ----------------------------------------------------

        parsed = raw.select(
            col("value"),
            regexp_extract(col("value"), LOG_PATTERN, 1).alias("host"),
            regexp_extract(col("value"), LOG_PATTERN, 2).alias("request_time"),
            regexp_extract(col("value"), LOG_PATTERN, 3).alias("method"),
            regexp_extract(col("value"), LOG_PATTERN, 4).alias("request"),
            regexp_extract(col("value"), LOG_PATTERN, 5).alias("protocol"),
            regexp_extract(col("value"), LOG_PATTERN, 6).alias("status_text"),
            regexp_extract(col("value"), LOG_PATTERN, 7).alias("bytes_text"),
        )

        # ----------------------------------------------------
        # 3. CLEAN AND TRANSFORM
        # ----------------------------------------------------

        logs_df = (
            parsed
            .filter(col("host") != "")
            .withColumn("status", col("status_text").cast("int"))
            .withColumn(
                "event_time",
                to_timestamp(
                    col("request_time"),
                    "dd/MMM/yyyy:HH:mm:ss Z",
                ),
            )
            .withColumn(
                "bytes",
                when(
                    col("bytes_text") == "-",
                    lit(0),
                ).otherwise(col("bytes_text").cast("long")),
            )
            .withColumn(
                "protocol",
                when(col("protocol") == "", "UNKNOWN").otherwise(col("protocol")),
            )
            .filter(
                col("status").isNotNull()
                & col("event_time").isNotNull()
                & col("bytes").isNotNull()
            )
        )

        logs_df.cache()
        logs_df.createOrReplaceTempView("weblogs")

        # ----------------------------------------------------
        # 4. DATA QUALITY REPORT
        # ----------------------------------------------------

        quality = validate_logs(raw, parsed, logs_df)

        # ----------------------------------------------------
        # 5. TOP IP ADDRESSES  (real Spark SQL, HiveQL-compatible)
        # ----------------------------------------------------

        print("\n=== TOP 15 IPs BY REQUEST VOLUME ===")

        top_ips = spark.sql("""
            SELECT host, COUNT(*) AS req_count
            FROM weblogs
            GROUP BY host
            ORDER BY req_count DESC
            LIMIT 15
        """)
        top_ips.show(15, truncate=False)

        # ----------------------------------------------------
        # 6. HTTP STATUS DISTRIBUTION  (real Spark SQL)
        # ----------------------------------------------------

        print("\n=== HTTP STATUS DISTRIBUTION ===")

        status_distribution = spark.sql("""
            SELECT
                status,
                CASE
                    WHEN status BETWEEN 200 AND 299 THEN '2xx Success'
                    WHEN status BETWEEN 300 AND 399 THEN '3xx Redirect'
                    WHEN status BETWEEN 400 AND 499 THEN '4xx Client Error'
                    WHEN status BETWEEN 500 AND 599 THEN '5xx Server Error'
                    ELSE 'Other'
                END AS status_category,
                COUNT(*) AS total
            FROM weblogs
            GROUP BY status, status_category
            ORDER BY total DESC
        """)
        status_distribution.show(20, truncate=False)

        # ----------------------------------------------------
        # 7. HTTP METHOD DISTRIBUTION  (real Spark SQL)
        # ----------------------------------------------------

        print("\n=== HTTP METHOD DISTRIBUTION ===")

        method_distribution = spark.sql("""
            SELECT method, COUNT(*) AS total
            FROM weblogs
            GROUP BY method
            ORDER BY total DESC
        """)
        method_distribution.show()

        # ----------------------------------------------------
        # 8. IP BEHAVIOR PROFILE
        # ----------------------------------------------------

        print("\n=== IP BEHAVIOR PROFILE ===")

        ip_profile = (
            logs_df.groupBy("host")
            .agg(
                count("*").alias("total_requests"),
                spark_sum(
                    when(col("status") == 404, 1).otherwise(0)
                ).alias("error_404_count"),
                spark_sum(
                    when(col("status") >= 400, 1).otherwise(0)
                ).alias("error_count"),
                countDistinct("request").alias("unique_urls"),
                avg("bytes").alias("avg_response_bytes"),
            )
            .withColumn(
                "error_rate_pct",
                spark_round(
                    col("error_count") / col("total_requests") * 100,
                    2,
                ),
            )
        )

        ip_profile.orderBy(
            col("total_requests").desc()
        ).show(15, truncate=False)

        # ----------------------------------------------------
        # 9. REQUESTS PER IP PER MINUTE
        # ----------------------------------------------------

        print("\n=== REQUESTS PER IP PER MINUTE ===")

        per_minute = (
            logs_df
            .groupBy(
                col("host"),
                window(col("event_time"), "1 minute"),
            )
            .agg(
                count("*").alias("requests_per_minute")
            )
        )

        per_minute.orderBy(
            col("requests_per_minute").desc()
        ).show(15, truncate=False)

        # ----------------------------------------------------
        # 10. SUSPICIOUS ACTIVITY DETECTION
        # ----------------------------------------------------
        # Heuristic only — flags candidates for human review, not proof of
        # an attack. Each rule can misfire on legitimate traffic, e.g. a
        # shared corporate proxy or AOL/Prodigy gateway can easily clear the
        # unique-URL or burst thresholds just by fronting many real users.

        print("\n=== POTENTIALLY SUSPICIOUS IPs ===")

        burst_ips = (
            per_minute
            .filter(
                col("requests_per_minute")
                >= MIN_REQUESTS_PER_MINUTE
            )
            .groupBy("host")
            .agg(
                spark_sum(
                    when(
                        col("requests_per_minute")
                        >= MIN_REQUESTS_PER_MINUTE,
                        1,
                    ).otherwise(0)
                ).alias("high_request_burst")
            )
        )

        suspects = (
            ip_profile
            .join(burst_ips, on="host", how="left")
            .fillna({"high_request_burst": 0})
            .withColumn(
                "suspicious",
                (
                    (col("error_404_count") >= MIN_404_ERRORS)
                    | (col("unique_urls") >= MIN_UNIQUE_URLS)
                    | (col("high_request_burst") > 0)
                ),
            )
            .filter(col("suspicious"))
            .withColumn(
                "reason",
                when(
                    col("high_request_burst") > 0,
                    "High request burst",
                )
                .when(
                    col("error_404_count") >= MIN_404_ERRORS,
                    "High number of 404 errors",
                )
                .otherwise("High number of unique URLs"),
            )
        )

        suspects.orderBy(
            col("total_requests").desc()
        ).show(50, truncate=False)

        # ----------------------------------------------------
        # 11. SAVE CSV REPORTS
        # ----------------------------------------------------

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs(REPORT_DIR, exist_ok=True)

        suspects.coalesce(1).write.mode("overwrite").option(
            "header", True
        ).csv(OUTPUT_DIR)

        # Convert the window STRUCT into separate timestamp columns
        per_minute_export = per_minute.select(
            col("host"),
            col("window.start").alias("window_start"),
            col("window.end").alias("window_end"),
            col("requests_per_minute"),
        )

        per_minute_export.coalesce(1).write.mode("overwrite").option(
            "header", True
        ).csv(
            os.path.join(REPORT_DIR, "requests_per_minute")
        )

        ip_profile.coalesce(1).write.mode("overwrite").option(
            "header", True
        ).csv(
            os.path.join(REPORT_DIR, "ip_behavior_profile")
        )

        status_distribution.coalesce(1).write.mode("overwrite").option(
            "header", True
        ).csv(
            os.path.join(REPORT_DIR, "status_distribution")
        )

        method_distribution.coalesce(1).write.mode("overwrite").option(
            "header", True
        ).csv(
            os.path.join(REPORT_DIR, "method_distribution")
        )

        # Single-row data-quality summary, so the dashboard and any future
        # tooling can load it exactly like the other reports instead of
        # only seeing it in the console output.
        quality_row = spark.createDataFrame([quality])
        quality_row.coalesce(1).write.mode("overwrite").option(
            "header", True
        ).csv(
            os.path.join(REPORT_DIR, "data_quality")
        )

        print("\n=== REPORTS SAVED ===")
        print(f"Suspicious IPs:        {OUTPUT_DIR}")
        print(f"Request windows:       {REPORT_DIR}/requests_per_minute")
        print(f"IP profiles:           {REPORT_DIR}/ip_behavior_profile")
        print(f"Status distribution:   {REPORT_DIR}/status_distribution")
        print(f"Method distribution:   {REPORT_DIR}/method_distribution")
        print(f"Data quality summary:  {REPORT_DIR}/data_quality")

    finally:
        spark.stop()


if __name__ == "__main__":
    run()
