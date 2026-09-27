"""
Shared constants and pure-Python helpers for weblog parsing.

Deliberately has NO dependency on PySpark (or anything else heavy) so that
the parsing logic can be unit-tested in any environment, including ones
where installing PySpark + Java isn't practical. spark_analysis.py imports
LOG_PATTERN from here rather than duplicating it.
"""

# The protocol token ("HTTP/1.0") is OPTIONAL: about 0.26% of lines in the
# NASA-HTTP dataset are real, well-formed requests that simply omit it
# (e.g. `"GET /ksc.html"` with no trailing HTTP version). Requiring it
# discarded ~4,900 legitimate records as "invalid" for no good reason.
LOG_PATTERN = (
    r'^(\S+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (\S+)(?: (\S+))?" (\d{3}) (\S+)$'
)

MIN_404_ERRORS = 20
MIN_UNIQUE_URLS = 100
MIN_REQUESTS_PER_MINUTE = 60

# All timestamps in the raw log carry an explicit UTC offset (e.g. "-0400").
# Reports display everything in UTC rather than the local timezone of
# whatever machine happens to run Spark, so results are reproducible.
REPORT_TIMEZONE = "UTC"


def status_category(status):
    """Bucket an HTTP status code into the category used across the
    dashboard and chart color scheme."""
    if 200 <= status <= 299:
        return "2xx Success"
    if 300 <= status <= 399:
        return "3xx Redirect"
    if 400 <= status <= 499:
        return "4xx Client Error"
    if 500 <= status <= 599:
        return "5xx Server Error"
    return "Other"
