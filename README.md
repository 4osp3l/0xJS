# 0xJS
0xJS is a AI-powered command-line tool that scans JavaScript files for sensitive information. It can identify API keys, credentials, tokens, and other medium to critical severity secrets with high accuracy ( also scans for potential security issues in JS ). It supports URLs/endpoints extraction, as well as minified-JS analysis.

# Prerequisites
- Python 3.7 or higher
- Google Gemini API key

# Installation

```bash
git clone https://github.com/4osp3l/0xJS
cd 0xJS
```

# Install dependencies

```bash
pip install -q -U google-genai
pip install python-dotenv
pip install requests
```

# Set up environment

```bash
touch .env
echo "GEMINI_API_KEY=your_api_key_here" > .env
```

# Quick Start ( One-Liner )
```bash
git clone https://github.com/4osp3l/0xJS.git && cd 0xJS && python main.py
```

# Usage 
```bash
usage: scanner.py [-h] --mode {sensitive,endpoints,security,config} [--url URL] [--file FILE] [--key KEY]

AI-Powered JavaScript Security Tool v3.0

optional arguments:
  -h, --help            Show this help message and exit
  --mode {sensitive,endpoints,security,config}
                        Scan mode (required)
  --url URL            Single URL to scan
  --file FILE          File containing list of URLs to scan (one per line)
  --key KEY            Configure API key (required for config mode)
```

> Configure API Key
```bash
python main.py --mode config --key "AIzaSyYourActualAPIKeyHere"
```
> Mode ( Sensitive Information Scan )
```bash
# Single URL
python scanner.py --mode sensitive --url "https://example.com/app.js"

# Multiple URLs from file
python scanner.py --mode sensitive --file "urls.txt"
```

# Support Me 
```bash
0x8ff0bf38a53f5d86d9e7b067d2c07d4abc58cb19
USDT ( ERC20 )
```

# Have a Feature Idea ?
> Open an issue !

# Disclaimer
> 0xJS is intended for authorized security testing and research only. Users are solely responsible for complying with all applicable laws and obtaining proper authorization before scanning any systems or applications.

# Responsible Disclosure
> If you discover sensitive information through 0xJS
- Document the finding with screenshots
- Contact the organization's security team
- Disclose responsibly through proper channels
- Never exfiltrate or misuse discovered secrets
