# 0xJS
0xJS is a AI-powered command-line tool that scans JavaScript files for sensitive information. It can identify API keys, credentials, tokens, and other medium to critical severity secrets with high accuracy.

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
pip install google-generativeai python-dotenv requests
```

# Set up environment

```bash
touch .env
echo "GEMINI_API_KEY=your_api_key_here" > .env
```

# Quick Start ( One-Liner )
```bash
git clone https://github.com/4osp3l/0xJS.git && cd 0xJS && pip install -r requirements.txt && python main.py
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
