# Clickwise

A beginner-friendly, rule-based URL checker. Paste a link and Clickwise scores how many warning signs its *text* contains, then explains each one. It never opens the link.

> Clickwise is a learning project. The score is a simple heuristic, not machine learning and not the probability that a site is phishing. A low score does not mean a site is safe, and a high score does not prove it is malicious.

## Features
- Enter a URL and get a risk score from 0 to 100 and a Low, Medium or High Risk category
- Shows every warning indicator that was triggered, with a short explanation
- 9 documented rules: IP address host, `@` in the address, long URL, many subdomains, suspicious words, URL shorteners, many hyphens, punycode / lookalike characters, and plain `http://`
- Related rules share a cap so the same oddity is not counted twice
- Invalid input (empty, malformed, unsupported schemes) is handled with a clear message
- Download the result as a CSV report, protected against CSV formula injection
- Responsive dark navy and teal design for phone and desktop
- 40 automated tests using Python's built-in `unittest`

## How the score works
| Rule | Points |
|---|---|
| IP address instead of a domain | +30 |
| `@` in the address part | +20 |
| Very long URL (100+ / 200+ characters) | +10 / +15 |
| 3 or more subdomains | +15 |
| Suspicious words (login, verify, account, secure, update, ...) | +10 each in the host, +4 each in the path, max 20 |
| URL shortener (small documented list) | +15 |
| 3 or more hyphens in the hostname | +10 |
| Punycode / non-English characters in the host | +15 |
| `http://` typed explicitly | +5 |

Suspicious words and hyphens share a combined cap of 25 points. The total is capped at 100.
**0 to 29** Low Risk, **30 to 59** Medium Risk, **60 to 100** High Risk. These cut-offs are illustrative, not scientifically validated.

## Tech used
Python 3, Flask, HTML, CSS, `urllib.parse`, `ipaddress`, `csv`, `unittest`

## Run it (Windows, VS Code)
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000 in your browser. Press Ctrl+C in the terminal to stop.

## Run the tests
```
python -m unittest discover -v
```

## Project structure
```
Clickwise/
  app.py            Flask routes (scan, download)
  detector.py       all the URL checking logic (no Flask code)
  report.py         CSV report + formula-injection protection
  requirements.txt
  templates/        base.html, index.html, result.html
  static/style.css
  tests/            unit tests
```

## Safety notes
- Submitted URLs are **never** visited, downloaded or executed
- Everything shown on the page is escaped by Jinja2, so a submitted URL cannot inject HTML
- CSV cells that start with `=`, `+`, `-` or `@` are neutralised
- Nothing is stored. No database, no scan history
- Debug mode is off. Do not turn it on for a public deployment

## Limitations
- Only looks at the text of a URL. It cannot check page content, redirects, SSL certificates, domain age or reputation databases
- The subdomain count is a simple estimate and can be wrong for domains like `example.co.uk`
- Does not understand unusual IP formats such as decimal (`http://3232235777`)
- The keyword and shortener lists are small and English-only
- Legitimate sites can score high and malicious sites can score low

## Screenshots
Add screenshots here after you run the app (home page, a Low Risk result, a High Risk result, mobile view).

## Test examples
These are made-up addresses (`example.com`, `example.test` and `203.0.113.x` are reserved for documentation):
- `https://www.example.com/about`
- `http://203.0.113.5/secure/login`
- `http://paypal.secure-login-verify.example.test@203.0.113.9/login?verify=1`
