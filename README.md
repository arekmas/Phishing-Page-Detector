# Phishing Page Detector

A Python tool that analyzes websites for potential phishing indicators. Checks domain WHOIS records, SSL certificates, page structure, and applies heuristic analysis to assess risk.

## Features

- **WHOIS lookup** - checks domain age, registrar, and expiration date
- **SSL verification** - validates certificate and checks days until expiry
- **Page structure analysis** - detects forms, iframes, redirects, and external links
- **Heuristic detection** - flags suspicious keywords, nested domains, and login page patterns
- **Auto-install** - missing dependencies are installed automatically

## Requirements

- Python 3.6+
- Internet connection

Dependencies (`requests`, `python-whois`) are installed automatically on first run.

## Installation

```bash
git clone https://github.com/arekmas/phishing-page-detector.git
cd phishing-page-detector
```

No manual installation needed. The script installs missing packages automatically.

## Usage

```bash
python phishing_detector.py https://example.com
```

Or run without arguments to enter the URL interactively:

```bash
python phishing_detector.py
```

## Example

```bash
python phishing_detector.py https://google.com
```

## License

GNU General Public License v3.0

See the [LICENSE](LICENSE) file for details.
