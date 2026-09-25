"""
Analysis stage: PySpark + Spark SQL (HiveQL-compatible), fulfilling the
'HIVE/PySpark for analysis' requirement without needing a separate Hadoop/Hive
cluster. Spark SQL runs the same HiveQL you'd write against a real Hive table.
"""
import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import regexp_extract, col

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INGESTED_DIR = os.path.join(BASE_DIR, "data", "ingested")
OUTPUT_DIR = os.path.join(BASE_DIR, "output", "suspicious_ips")

# Common Log Format, e.g.:
# 199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245
LOG_PATTERN = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)$'


def run():
    spark = (
        SparkSession.builder
        .appName("WeblogIntrusionAnalysis")
        .master("local[*]")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")

    raw = spark.read.text(INGESTED_DIR)

    logs_df = raw.select(
        regexp_extract("value", LOG_PATTERN, 1).alias("host"),
        regexp_extract("value", LOG_PATTERN, 2).alias("request_time"),
        regexp_extract("value", LOG_PATTERN, 3).alias("method"),
        regexp_extract("value", LOG_PATTERN, 4).alias("request"),
        regexp_extract("value", LOG_PATTERN, 5).alias("protocol"),
        regexp_extract("value", LOG_PATTERN, 6).cast("int").alias("status"),
        regexp_extract("value", LOG_PATTERN, 7).alias("bytes"),
    ).filter(col("host") != "")

    logs_df.createOrReplaceTempView("weblogs")

    print("\n=== Q1: Top 15 IPs by request volume ===")
    spark.sql("""
        SELECT host, COUNT(*) AS req_count
        FROM weblogs GROUP BY host
        ORDER BY req_count DESC LIMIT 15
    """).show(truncate=False)

    print("=== Q2: Suspicious IPs (404 count > 50 -> likely scanning) ===")
    suspects = spark.sql("""
        SELECT host, COUNT(*) AS error_404_count
        FROM weblogs WHERE status = 404
        GROUP BY host HAVING COUNT(*) > 50
        ORDER BY error_404_count DESC
    """)
    suspects.show(truncate=False)

    print("=== Q3: HTTP status code distribution ===")
    spark.sql("""
        SELECT status, COUNT(*) AS count
        FROM weblogs GROUP BY status ORDER BY count DESC
    """).show()

    print("=== Q4: HTTP method distribution ===")
    spark.sql("""
        SELECT method, COUNT(*) AS count
        FROM weblogs GROUP BY method ORDER BY count DESC
    """).show()

    suspects.coalesce(1).write.mode("overwrite").option("header", True).csv(OUTPUT_DIR)
    print(f"Suspicious IP results saved to: {OUTPUT_DIR}")

    spark.stop()


if __name__ == "__main__":
    run()
