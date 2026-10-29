"""
detector.py - the rule-based URL checker for Clickwise.

This file has NO Flask code. It only takes a piece of text, checks it against a
small set of simple rules, and returns a dictionary with a score and a list of
the warning indicators it found.

IMPORTANT: this is a teaching/demo heuristic. It never visits the URL, it is not
machine learning, and the score is not a probability that a site is phishing.
"""

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Settings. All the numbers live here so they are easy to find and explain.
# ---------------------------------------------------------------------------
MAX_INPUT_LENGTH = 2048          # refuse anything longer than this (basic abuse protection)

LONG_URL_MEDIUM = 100            # characters
LONG_URL_HIGH = 200
SUBDOMAIN_LIMIT = 3              # this many subdomains or more is "unusual"
HYPHEN_LIMIT = 3                 # this many hyphens in the hostname or more is "unusual"

# Words that often appear in phishing links. They also appear in normal links,
# so they only add a LOW number of points.
SUSPICIOUS_WORDS = ("login", "signin", "verify", "account", "secure", "update", "password", "confirm")

# A small, documented list of well-known URL shortening domains.
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Points for each rule.
POINTS_IP_HOST = 30
POINTS_AT_SYMBOL = 20
POINTS_LONG_MEDIUM = 10
POINTS_LONG_HIGH = 15
POINTS_SUBDOMAINS = 15
POINTS_SHORTENER = 15
POINTS_HYPHENS = 10
POINTS_PUNYCODE = 15
POINTS_PLAIN_HTTP = 5            # deliberately small: HTTP alone is not proof of anything
POINTS_WORD_IN_HOST = 10         # per word found in the host part
POINTS_WORD_IN_PATH = 4          # per word found in the path/query (lower, because "/login" is normal)
WORDS_MAX_POINTS = 20

# Some rules overlap (for example "secure-login-verify" has many hyphens AND
# many keywords). To avoid counting the same weirdness twice, related rules
# share a cap on how many points they can add together.
WORDING_GROUP_CAP = 25           # applies to: suspicious words + many hyphens

# Score -> category. These thresholds are illustrative, not scientifically validated.
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60

# Used on the website to show how scoring works (single source of truth).
RULE_DOCS = [
    ("IP address instead of a domain", f"+{POINTS_IP_HOST}", "Real sites usually use a name, not a number."),
    ("@ symbol in the address part", f"+{POINTS_AT_SYMBOL}", "Text before @ is ignored by browsers, so it can be used to mislead."),
    ("Very long URL", f"+{POINTS_LONG_MEDIUM} to +{POINTS_LONG_HIGH}", f"{LONG_URL_MEDIUM}+ characters, or {LONG_URL_HIGH}+ for the higher amount."),
    ("Many subdomains", f"+{POINTS_SUBDOMAINS}", f"{SUBDOMAIN_LIMIT} or more parts before the main domain."),
    ("Suspicious words", f"+{POINTS_WORD_IN_HOST} each in the host, +{POINTS_WORD_IN_PATH} each in the path", f"Max {WORDS_MAX_POINTS}. Words: {', '.join(SUSPICIOUS_WORDS)}."),
    ("URL shortener", f"+{POINTS_SHORTENER}", "The real destination is hidden behind a short link."),
    ("Many hyphens in the hostname", f"+{POINTS_HYPHENS}", f"{HYPHEN_LIMIT} or more hyphens."),
    ("Punycode or non-English characters in the host", f"+{POINTS_PUNYCODE}", "Lookalike letters can imitate a real domain."),
    ("Plain http:// typed in the link", f"+{POINTS_PLAIN_HTTP}", "A weak signal only. https:// does not mean a site is safe either."),
]

NON_WEB_PREFIXES = ("javascript:", "data:", "mailto:", "file:", "vbscript:", "tel:", "ftp:")
LABEL_PATTERN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _now_text():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _failure(raw, message):
    """What we return when the input can't be analysed."""
    return {"valid": False, "error": message, "input": raw if isinstance(raw, str) else "", "scanned_at": _now_text()}


def categorise(score):
    """Turn a number into a category name and a short code used for colours."""
    if score >= HIGH_THRESHOLD:
        return "High Risk", "high"
    if score >= MEDIUM_THRESHOLD:
        return "Medium Risk", "medium"
    return "Low Risk", "low"


def find_words(text):
    """
    Find suspicious words in some text. We split the text into whole tokens
    (letters/numbers) so 'accounting' does NOT match 'account'.
    """
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [word for word in SUSPICIOUS_WORDS if word in tokens]


def _apply_cap(indicators, ids, cap):
    """Trim points on related indicators so together they never exceed `cap`."""
    running_total = 0
    for item in indicators:
        if item["id"] not in ids:
            continue
        allowed = max(0, cap - running_total)
        if item["points"] > allowed:
            item["points"] = allowed
            item["detail"] += " (Points reduced because related warnings overlap.)"
        running_total += item["points"]


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------
def analyze_url(raw_input):
    """Check one URL and return a dictionary describing the result."""

    # 1. Basic input checks ---------------------------------------------------
    if not isinstance(raw_input, str):
        return _failure("", "Please enter a URL.")
    raw = raw_input.strip()
    if not raw:
        return _failure(raw, "Please enter a URL.")
    if len(raw) > MAX_INPUT_LENGTH:
        return _failure(raw[:100], f"That URL is too long to analyse (the limit is {MAX_INPUT_LENGTH} characters).")
    if re.search(r"\s", raw) or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return _failure(raw, "A URL cannot contain spaces or hidden control characters.")
    if "\\" in raw:
        return _failure(raw, "This link contains a backslash, which browsers handle in unexpected ways. Treat it with caution.")

    # 2. Work out the scheme (http/https) -------------------------------------
    lowered = raw.lower()
    assumed_scheme = False
    typed_http = False
    if "://" in raw:
        scheme = lowered.split("://", 1)[0]
        if scheme not in ("http", "https"):
            return _failure(raw, "Only http:// and https:// links are supported.")
        candidate = raw
        typed_http = scheme == "http"
    elif lowered.startswith(NON_WEB_PREFIXES):
        return _failure(raw, "Only http:// and https:// links are supported.")
    elif raw.startswith("//"):
        candidate, assumed_scheme = "http:" + raw, True
    else:
        candidate, assumed_scheme = "http://" + raw, True   # only so we can parse it

    # 3. Parse with urllib.parse (we never connect to the address) -------------
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        parsed.port                       # reading the port raises ValueError if it is invalid
    except ValueError:
        return _failure(raw, "This URL could not be parsed. Check for typos in the address or port.")
    if not hostname:
        return _failure(raw, "No hostname was found in this URL.")
    hostname = hostname.rstrip(".")

    # 4. Is the hostname an IP address or a proper domain name? ---------------
    host_is_ip = False
    try:
        ipaddress.ip_address(hostname)    # handles IPv4 and IPv6
        host_is_ip = True
    except ValueError:
        pass

    ascii_host = hostname
    if not host_is_ip:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")   # converts non-English letters to punycode
        except UnicodeError:
            return _failure(raw, "The hostname contains characters that are not allowed.")
        labels = ascii_host.split(".")
        if (len(ascii_host) > 253 or len(labels) < 2
                or any(not LABEL_PATTERN.fullmatch(label) for label in labels)
                or labels[-1].isdigit()):
            return _failure(raw, "The hostname is not a valid domain name or IP address.")

    # 5. Run the rules --------------------------------------------------------
    indicators = []

    def add(rule_id, title, detail, points):
        indicators.append({"id": rule_id, "title": title, "detail": detail, "points": points})

    # Rule: IP address host
    if host_is_ip:
        add("ip_host", "IP address used instead of a domain name",
            "The link points to a number like 203.0.113.5 instead of a normal website name. Legitimate sites rarely do this.",
            POINTS_IP_HOST)

    # Rule: "@" in the address part (everything before the first "/" is the authority)
    if "@" in parsed.netloc:
        add("at_symbol", "Contains an @ symbol in the address part",
            "Browsers ignore the text before @ and go to what comes after it, so attackers can put a trusted-looking name first.",
            POINTS_AT_SYMBOL)

    # Rule: very long URL
    length = len(raw)
    if length >= LONG_URL_HIGH:
        add("long_url", "Unusually long URL", f"The URL is {length} characters long. Long links can hide the real destination.", POINTS_LONG_HIGH)
    elif length >= LONG_URL_MEDIUM:
        add("long_url", "Long URL", f"The URL is {length} characters long. Long links can hide the real destination.", POINTS_LONG_MEDIUM)

    # Rule: many subdomains (skipped for IP addresses). We ignore a leading "www".
    if not host_is_ip:
        labels = ascii_host.split(".")
        if labels[0] == "www":
            labels = labels[1:]
        subdomain_count = max(0, len(labels) - 2)     # simple estimate, see README limitations
        if subdomain_count >= SUBDOMAIN_LIMIT:
            add("many_subdomains", "Many subdomains",
                f"The hostname has about {subdomain_count} subdomains. Attackers stack names so a trusted brand appears early in the address.",
                POINTS_SUBDOMAINS)

    # Rule: suspicious words (host part counts more than the path)
    host_part = parsed.netloc
    path_part = parsed.path + " " + parsed.query + " " + parsed.fragment
    host_words = find_words(host_part)
    path_words = [w for w in find_words(path_part) if w not in host_words]
    if host_words or path_words:
        points = min(WORDS_MAX_POINTS, POINTS_WORD_IN_HOST * len(host_words) + POINTS_WORD_IN_PATH * len(path_words))
        found = ", ".join(host_words + path_words)
        add("suspicious_words", "Suspicious words in the URL",
            f"Found: {found}. These words are common on real sites too, so this is only a weak signal on its own.",
            points)

    # Rule: URL shortener
    if any(ascii_host == d or ascii_host.endswith("." + d) for d in SHORTENER_DOMAINS):
        add("url_shortener", "Shortened link",
            "The real destination is hidden behind a short link. Clickwise does not visit links, so it cannot see where this one goes.",
            POINTS_SHORTENER)

    # Rule: many hyphens in the hostname
    hyphen_count = hostname.count("-")
    if not host_is_ip and hyphen_count >= HYPHEN_LIMIT:
        add("many_hyphens", "Many hyphens in the hostname",
            f"The hostname has {hyphen_count} hyphens. Names like secure-login-bank-update are a common trick.",
            POINTS_HYPHENS)

    # Rule: punycode / non-English characters
    if not host_is_ip and (hostname != ascii_host or any(l.startswith("xn--") for l in ascii_host.split("."))):
        add("punycode", "Special characters in the hostname",
            "The hostname uses non-English characters (punycode). Lookalike letters can imitate a real domain.",
            POINTS_PUNYCODE)

    # Rule: plain http typed explicitly (small weight, never proof)
    if typed_http:
        add("plain_http", "Link uses http:// instead of https://",
            "This is only a weak signal. Many harmless sites still use http, and many phishing sites use https.",
            POINTS_PLAIN_HTTP)

    # 6. Related rules share a cap, then add everything up ---------------------
    _apply_cap(indicators, {"suspicious_words", "many_hyphens"}, WORDING_GROUP_CAP)
    indicators = [i for i in indicators if i["points"] > 0]
    score = min(100, sum(i["points"] for i in indicators))
    category, level = categorise(score)

    return {
        "valid": True,
        "error": None,
        "input": raw,
        "analysed_as": candidate,
        "assumed_scheme": assumed_scheme,
        "hostname": ascii_host,
        "score": score,
        "category": category,
        "level": level,
        "indicators": indicators,
        "scanned_at": _now_text(),
    }
