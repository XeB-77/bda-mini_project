
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
)

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INGESTED_DIR = os.path.join(BASE_DIR, "data", "ingested")
OUTPUT_DIR = os.path.join(BASE_DIR, "output", "suspicious_ips")
REPORT_DIR = os.path.join(BASE_DIR, "output", "reports")

MIN_404_ERRORS = 20
MIN_UNIQUE_URLS = 100
MIN_REQUESTS_PER_MINUTE = 60

LOG_PATTERN = (
    r'^(\S+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (\S+) (\S+)" (\d{3}) (\S+)$'
)


# ============================================================
# DATA QUALITY VALIDATION
# ============================================================

def validate_logs(raw, logs_df):
    """Generate data quality metrics for the weblog dataset."""

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

    missing_ips = logs_df.filter(
        col("host").isNull() | (trim(col("host")) == "")
    ).count()

    print("\n" + "=" * 55)
    print("DATA QUALITY REPORT")
    print("=" * 55)
    print(f"Total records:       {total}")
    print(f"Valid records:       {valid}")
    print(f"Invalid records:     {invalid}")
    print(f"Duplicate records:   {duplicates}")
    print(f"Missing IP records:  {missing_ips}")
    print("=" * 55)

    return {
        "total": total,
        "valid": valid,
        "invalid": invalid,
        "duplicates": duplicates,
        "missing_ips": missing_ips,
    }


# ============================================================
# MAIN ANALYSIS
# ============================================================

def run():

    spark = (
        SparkSession.builder
        .appName("WeblogIntrusionAnalysis")
        .master("local[*]")
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
                    0,
                ).otherwise(col("bytes_text").cast("long")),
            )
            .filter(
                col("status").isNotNull()
                & col("event_time").isNotNull()
                & col("bytes").isNotNull()
            )
        )

        # ----------------------------------------------------
        # 4. DATA QUALITY REPORT
        # ----------------------------------------------------

        quality = validate_logs(raw, logs_df)

        # ----------------------------------------------------
        # 5. TOP IP ADDRESSES
        # ----------------------------------------------------

        print("\n=== TOP 15 IPs BY REQUEST VOLUME ===")

        spark.sql("""
            SELECT host, COUNT(*) AS req_count
            FROM (
                SELECT host FROM weblogs_placeholder
            )
            GROUP BY host
            ORDER BY req_count DESC
            LIMIT 15
        """) if False else None

        logs_df.groupBy("host").agg(
            count("*").alias("req_count")
        ).orderBy(
            col("req_count").desc()
        ).show(15, truncate=False)

        # ----------------------------------------------------
        # 6. HTTP STATUS DISTRIBUTION
        # ----------------------------------------------------

        print("\n=== HTTP STATUS DISTRIBUTION ===")

        logs_df.groupBy("status").agg(
            count("*").alias("total")
        ).orderBy(
            col("total").desc()
        ).show()

        # ----------------------------------------------------
        # 7. HTTP METHOD DISTRIBUTION
        # ----------------------------------------------------

        print("\n=== HTTP METHOD DISTRIBUTION ===")

        logs_df.groupBy("method").agg(
            count("*").alias("total")
        ).orderBy(
            col("total").desc()
        ).show()

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

        print("\n=== REPORTS SAVED ===")
        print(f"Suspicious IPs: {OUTPUT_DIR}")
        print(f"Request windows: {REPORT_DIR}/requests_per_minute")
        print(f"IP profiles: {REPORT_DIR}/ip_behavior_profile")

    finally:
        spark.stop()


if __name__ == "__main__":
    run()