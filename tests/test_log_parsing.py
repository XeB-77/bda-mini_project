"""
Unit tests for the parsing/categorization logic in spark_analysis.py.

These test the LOG_PATTERN regex and status-category rules directly in
pure Python, without requiring PySpark to be installed — useful for quick
iteration, and for CI environments where installing PySpark + Java is
impractical. This does NOT replace actually running spark_analysis.py
against real data; see PROJECT_AUDIT_HANDOFF.md for what was and wasn't
run end-to-end in PySpark itself.

Run with:
    python -m unittest tests/test_log_parsing.py -v
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_patterns import LOG_PATTERN, status_category  # noqa: E402

PATTERN = re.compile(LOG_PATTERN)


class TestLogPattern(unittest.TestCase):

    def test_well_formed_line(self):
        line = (
            '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] '
            '"GET /history/apollo/ HTTP/1.0" 200 6245'
        )
        m = PATTERN.match(line)
        self.assertIsNotNone(m)
        host, ts, method, path, proto, status, nbytes = m.groups()
        self.assertEqual(host, "199.72.81.55")
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/history/apollo/")
        self.assertEqual(proto, "HTTP/1.0")
        self.assertEqual(status, "200")
        self.assertEqual(nbytes, "6245")

    def test_hostname_client(self):
        line = (
            'pipe6.nyc.pipeline.com - - [01/Jul/1995:00:22:43 -0400] '
            '"GET /shuttle/missions/sts-71/movies/sts-71-mir-dock.mpg '
            'HTTP/1.0" 200 946425'
        )
        m = PATTERN.match(line)
        self.assertIsNotNone(m)

    def test_missing_protocol_is_recovered(self):
        # This is the real-world case that was previously dropped as
        # "invalid": a well-formed request missing the trailing HTTP
        # version token. The fixed regex must still parse it.
        line = (
            'columbia.acc.brad.ac.uk - - [01/Jul/1995:00:51:31 -0400] '
            '"GET /ksc.html" 200 7074'
        )
        m = PATTERN.match(line)
        self.assertIsNotNone(m)
        host, ts, method, path, proto, status, nbytes = m.groups()
        self.assertEqual(host, "columbia.acc.brad.ac.uk")
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/ksc.html")
        self.assertIsNone(proto)  # non-participating group
        self.assertEqual(status, "200")

    def test_dash_bytes_field(self):
        line = (
            '1.2.3.4 - - [01/Jul/1995:00:00:01 -0400] '
            '"GET /favicon.ico HTTP/1.0" 404 -'
        )
        m = PATTERN.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(7), "-")

    def test_genuinely_malformed_line_does_not_match(self):
        line = "this is not a log line at all"
        self.assertIsNone(PATTERN.match(line))

    def test_empty_line_does_not_match(self):
        self.assertIsNone(PATTERN.match(""))


class TestStatusCategory(unittest.TestCase):

    def test_categories(self):
        self.assertEqual(status_category(200), "2xx Success")
        self.assertEqual(status_category(304), "3xx Redirect")
        self.assertEqual(status_category(404), "4xx Client Error")
        self.assertEqual(status_category(500), "5xx Server Error")
        self.assertEqual(status_category(700), "Other")


class TestAgainstRealDataset(unittest.TestCase):
    """
    Sanity-checks the parsing rate against the real ingested dataset, if
    present. Skips itself if the dataset hasn't been downloaded/ingested
    yet, so this suite still runs cleanly on a fresh checkout.
    """

    def test_match_rate_is_high(self):
        log_path = (
            Path(__file__).resolve().parent.parent
            / "data" / "ingested" / "NASA_access_log_Jul95.COMPLETED"
        )
        if not log_path.exists():
            self.skipTest("Dataset not ingested in this environment.")

        total = 0
        matched = 0
        with open(log_path, errors="replace") as f:
            for line in f:
                total += 1
                if PATTERN.match(line.rstrip("\n")):
                    matched += 1

        match_rate = matched / total if total else 0
        # The known-malformed residual in this dataset is ~0.10%.
        self.assertGreater(match_rate, 0.998)


if __name__ == "__main__":
    unittest.main()
