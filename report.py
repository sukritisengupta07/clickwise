"""
report.py - builds the CSV report.

The URL comes from the user, so it is untrusted. If a cell starts with = + - @
a spreadsheet program (Excel, Sheets) could treat it as a formula. That is called
CSV formula injection. csv_safe() prevents it by adding a ' in front.
"""

import csv
import io

DANGEROUS_STARTS = ("=", "+", "-", "@")


def csv_safe(value):
    """Return text that is safe to put in a spreadsheet cell."""
    text = "" if value is None else str(value)
    stripped = text.lstrip(" ")
    if stripped.startswith(DANGEROUS_STARTS) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def build_csv(result):
    """Turn a result dictionary from detector.analyze_url() into CSV text."""
    if result["indicators"]:
        indicator_text = "; ".join(f"{i['title']} (+{i['points']})" for i in result["indicators"])
    else:
        indicator_text = "No configured warning indicators detected"

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["Scanned at", "Submitted URL", "Risk score (0-100)", "Risk category", "Indicators detected", "Note"])
    writer.writerow([csv_safe(x) for x in [
        result["scanned_at"],
        result["input"],
        result["score"],
        result["category"],
        indicator_text,
        "Heuristic result for learning purposes. Not a verdict on whether the site is safe.",
    ]])
    return output.getvalue()
