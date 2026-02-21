# 0xJS v4.0
0xJS is an AI-powered JavaScript Security Tool

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
python main.py --mode sensitive --url "https://example.com/app.js"

# Multiple URLs from file
python main.py --mode sensitive --file "urls.txt"
```
> URLs/Endpoints Extraction
```bash
# Single URL
python main.py --mode endpoints --url "https://example.com/app.js"

# Multiple URLs from file
python main.py --mode endpoints --file "urls.txt"
```
> Security Vulnerability Scan
```bash
# Single URL
python main.py --mode security --url "https://example.com/app.js"

# Multiple URLs from file
python main.py --mode security --file "urls.txt"
```

# Discord Webhook Integration
> The tool can send scan results and notifications to a Discord channel via webhooks.

> Setup Instructions
- Create a Discord server
- Open your Discord server settings
- Go to Integrations → Webhooks
- Click Create Webhook
- Name your webhook ( e.g., "0xJS" )
- Select the channel where notifications should appear ( i.e "general" )
- Copy the Webhook URL

> Configure the Webhook in the Tool

- Create a .webhook file in the root directory of the tool 
```bash
echo "https://discord.com/api/webhooks/your-webhook-url-here" > .webhook
```

# Limitations
- Maximum file size - 800,000 characters per JavaScript file
- Larger files should be split using the ./chunk.py utility ( host locally and try again ).
- Requires active internet connection for API calls
- API rate limits apply based on your Gemini plan

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
