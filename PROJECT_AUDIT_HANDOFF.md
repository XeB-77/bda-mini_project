# Project Audit Handoff

Audit and remediation pass on the Weblog Intrusion Analysis (NASA-HTTP)
BDA mini project. This document is the honest record of what was
inspected, changed, tested, and NOT tested — per the audit brief's
explicit requirement not to claim untested things passed.

## Environment Constraints (read this first)

This audit was performed in a sandbox with **no network access** and
**no PySpark/Streamlit/Plotly/Scapy pre-installed**, and `pip install`
could not reach any package index. This materially shaped what could be
verified directly:

| Available in this sandbox | NOT available |
|---|---|
| Python 3.12, Java 21 (OpenJDK) | PySpark |
| pandas, matplotlib | Streamlit |
| Your actual uploaded project + real dataset (1,891,715 log lines) | Plotly |
| | Scapy |
| | Any network access (no pip installs, no live packet capture) |

Because PySpark itself could not be run here, **every numeric claim below
was independently verified using a pure-Python equivalent implementation
of the corrected `spark_analysis.py` logic**, run directly against your
real ingested log file (not synthetic data), and cross-checked. The
actual `spark_analysis.py` in this delivery is the real, intended
PySpark implementation — the pure-Python version was a verification tool
only, never shipped as part of the project.

## What Was Inspected

Every source file was read in full: `download_dataset.py`,
`flume_style_ingest.py`, `spark_analysis.py`, `network_monitor.py`,
`run_all.py`, `visualize_reports.py`, `dashboard.py`, `README.md`,
`requirements.txt`, `setup.txt`, plus the actual generated contents of
`output/` (existing CSV reports, PNG charts, `summary_report.txt`) and
the raw/ingested dataset itself.

## Bugs Found & Fixed (all confirmed against real data, not assumed)

1. **Dead code**: `spark_analysis.py` had a `spark.sql(...) if False else
   None` block — never executed, despite the README claiming Spark SQL
   was used. **Fix:** removed; replaced with genuine `spark.sql()`
   queries (top IPs, status distribution, method distribution) against a
   registered temp view.

2. **`missing_ips` metric always returned 0.** It was computed on
   `logs_df`, which was already filtered to `host != ""` — so the
   condition it checked could never be true. **Fix:** now computed on
   the pre-filter `parsed` DataFrame. Verified: on the real dataset this
   now correctly reports 1,958 unparsable lines (previously silently 0).

3. **Regex was too strict, dropping legitimate records.** ~4,877 lines
   (0.26% of the dataset) are well-formed requests missing the trailing
   HTTP protocol token (e.g. `"GET /ksc.html"`), which the old regex
   required. **Verified independently** with a standalone regex test
   against the real log file before and after the fix: unmatched lines
   dropped from 4,877 to 1,958 (the residual is genuinely corrupted
   lines — extra whitespace, garbled request fields). **Fix:** made the
   protocol group optional in `log_patterns.py`.

4. **Timezone bug in exported reports.** `requests_per_minute` window
   timestamps were rendered in the Spark session's local timezone
   (observed as `+05:30` in the existing `output/` folder) instead of a
   fixed, documented zone — misleading for a report about 1995 Florida
   (EDT, `-0400`) traffic. **Fix:** pinned
   `spark.sql.session.timeZone` to UTC and documented this in the code
   and README.

5. **HTTP status and method distributions were computed but never
   saved** — only printed to the console during the Spark run, so the
   dashboard had no way to display them (confirmed by reading the old
   `dashboard.py`, which had an explicit comment admitting this gap).
   **Fix:** both are now persisted as CSV reports
   (`output/reports/status_distribution`, `.../method_distribution`).

6. **Data-quality metrics (total/valid/invalid/duplicates) were never
   persisted anywhere**, only printed. **Fix:** now written to
   `output/reports/data_quality` as a single-row CSV; the dashboard's
   Overview page reads it and falls back gracefully with a clear message
   if it's missing (e.g. against an older `output/` folder).

7. **Dashboard's "Other Error Responses" metric was mislabeled.** It
   displayed `error_count` (status ≥ 400, which *includes* 404s)
   alongside a separate "404 Responses" metric, implying they were
   additive when 404s are a subset of the total. **Fix:** relabeled to
   "Other 4xx/5xx Errors" (= `error_count - error_404_count`) and "Total
   4xx/5xx Errors" (= `error_count`), with tooltips clarifying the
   relationship. Added a real status-code breakdown chart (previously
   the page had an `st.info()` admitting this data didn't exist).

8. **Redundant/dead filter logic** in the Suspicious IPs page: it
   re-filtered `suspicious["suspicious"] == True` on data that was
   already pre-filtered to suspicious hosts upstream. Removed as
   simplification (harmless, but confusing).

9. **`network_monitor.py`**:
   - Baseline request/error limits only matched numeric-dotted IPs via
     regex, silently ignoring the majority of NASA-log clients, which
     are named hosts (`pipe6.nyc.pipeline.com`, etc.). **Verified**: old
     regex matched a small fraction of lines; the fixed regex matches
     1,891,700 of 1,891,715 lines (99.999%).
   - Used a relative path (`data/ingested`) that breaks depending on the
     working directory the script is launched from, inconsistent with
     every other script in the project. Fixed to use a `BASE_DIR`-
     relative path, matching the rest of the codebase.
   - Ran `sniff()` at import time with no `if __name__ == "__main__":`
     guard, so merely importing the module would start live packet
     capture. Fixed, plus added explicit error handling for permission
     and interface errors with actionable messages.

10. **Documentation/implementation mismatches**: the README overstated
    Spark SQL/Hive usage (fixed by making it true — see #1), didn't
    mention `dashboard.py` or `visualize_reports.py` at all, and
    `run_all.py`'s docstring said "Spark/Hive-SQL analysis" without
    qualification. README fully rewritten; `run_all.py` now also runs
    the visualization step so one command produces the full deliverable.

## Files Modified

- `spark_analysis.py` — rewritten (see bugs #1–6)
- `log_patterns.py` — **new** file; regex/thresholds factored out so they
  can be unit-tested without requiring PySpark to be installed
- `dashboard.py` — full dark cybersecurity-theme redesign (CSS + Plotly
  dark template + consistent status/severity color mapping across every
  page), plus bug fixes #7–8, plus new Data Quality section, HTTP status
  breakdown, and detection-rule explanation on the Suspicious IPs page
- `visualize_reports.py` — added a status-distribution chart, folded
  data-quality numbers into `summary_report.txt`, fixed an unreadable
  overplotted "requests over time" chart by aggregating to daily buckets
- `network_monitor.py` — rewritten (see bug #9)
- `run_all.py` — now runs `visualize_reports.py` as a final step; fixed
  docstring accuracy
- `requirements.txt` — bumped `pyspark` to `>=4.0.0` (required for
  Python 3.12+; the old unconstrained `>=3.4` would fail to install
  cleanly on modern Python)
- `setup.txt`, `README.md` — rewritten for accuracy and completeness
- `tests/test_log_parsing.py` — **new**; runnable without PySpark
- `output/reports/*`, `output/suspicious_ips/*`,
  `output/visualizations/*` — regenerated to reflect the corrected
  pipeline logic (see verification note below)

## Tests Actually Performed (and passed)

- `python -m py_compile` on every modified `.py` file — all pass.
- `python -m unittest tests/test_log_parsing.py -v` — **8/8 tests pass**,
  including a live check against the real 1,891,715-line dataset
  (asserts match rate > 99.8%; actual measured rate ≈ 99.90%).
- `python3 visualize_reports.py` — **actually executed** in this sandbox
  (pandas/matplotlib are available here) against the regenerated CSV
  reports. Produced all 7 PNG charts plus `summary_report.txt`; several
  charts were visually inspected as images to confirm they render
  correctly (status distribution log-scale chart, daily traffic chart).
- The corrected parsing regex, the `missing_ips` fix, the data-quality
  breakdown, and the `network_monitor.py` baseline-regex fix were each
  independently verified with standalone scripts run against your real
  ingested log file (not synthetic/assumed data) — exact before/after
  counts are in the bug list above.
- The full report set (`data_quality`, `status_distribution`,
  `method_distribution`, `ip_behavior_profile`, `requests_per_minute`,
  `suspicious_ips`) was regenerated using a pure-Python line-for-line
  equivalent of the new Spark logic (same regex, same thresholds, same
  schemas) and written into `output/`, so the delivered `output/` folder
  is consistent with the corrected code.

## Tests NOT Performed (and why)

- **`spark_analysis.py` was never executed via actual PySpark.** No
  PySpark install was possible in this sandbox (no network). The pure-
  Python equivalent used for regeneration mirrors the same logic
  line-for-line, but it is not a substitute for actually running the
  real Spark job. **You should run `python spark_analysis.py` yourself
  before submission** to confirm it executes cleanly end-to-end in your
  real environment — this is the single most important remaining
  verification step.
- **`dashboard.py` was never launched with `streamlit run`.** Streamlit
  isn't installed here. It was compile-checked (`py_compile`) and
  carefully reasoned through line-by-line, including tracing every
  DataFrame column it reads back to the reports that produce them, but
  **no one has visually seen the redesigned dashboard render.** Run
  `streamlit run dashboard.py` and click through all six pages before
  submission.
- **`network_monitor.py` was never run.** No Scapy, no live NIC access,
  no root in this sandbox. Only compile-checked and manually reviewed;
  its baseline-regex fix was verified separately in pure Python.
- **`download_dataset.py` was never executed** (no network access to
  fetch the actual archive). It was reviewed for correctness but not
  run.
- Browser-based interaction testing (clicking filters, download buttons,
  etc. in the actual running dashboard) was **not** performed, per the
  above.

## Known Remaining Issues / Suggestions

- A residual ~0.10% of log lines remain genuinely unparsable even after
  the regex fix (extra whitespace, corrupted request fields) — this is
  now honestly reported via the data-quality metrics rather than hidden.
- `network_monitor.py`'s baseline limits remain a rough heuristic (max of
  a fixed floor and a fraction of historical request/error volume), not
  a statistically fitted threshold — stated explicitly in its docstring
  now rather than implied to be more rigorous than it is.
- The IP Behavior page's scatter chart still uses Plotly's default
  continuous color scale rather than the custom theme palette — cosmetic
  only, left as-is given time constraints; safe to leave or restyle.

## Exact Commands to Run the Project

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt        # needs Java 17/21 already installed
python run_all.py                      # download -> ingest -> analyze -> visualize
python -m unittest tests/test_log_parsing.py -v   # optional, runs in seconds
streamlit run dashboard.py
```
