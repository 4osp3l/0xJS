import os
import sys
import argparse
import requests
from dotenv import load_dotenv

# Correct import for the current google-genai SDK (2025–2026)
from google import genai

try:
    import webview
except ImportError:
    webview = None

load_dotenv()

# ────────────────────────────────────────
#  Globals / Config
# ────────────────────────────────────────

WEBHOOK_URL = None
try:
    if os.path.exists(".webhook"):
        with open(".webhook", encoding="utf-8") as f:
            WEBHOOK_URL = f.read().strip()
except:
    pass

MAX_CHARS = 800_000
MODEL_NAME = "gemini-2.5-flash"  # Change if needed (e.g. gemini-1.5-flash, gemini-2.5-flash-preview-...)

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    print("[-] GEMINI_API_KEY missing in .env")
    sys.exit(1)

# Create client once (recommended pattern)
client = genai.Client(api_key=API_KEY)

def send_to_webhook(text: str, prefix: str = "", url: str = ""):
    if not WEBHOOK_URL:
        return
    try:
        content = f"{prefix} @ {url}\n\n{text}"[:3000]
        requests.post(WEBHOOK_URL, json={"content": content}, timeout=6)
    except:
        print("[Webhook failed - continuing]")

# ────────────────────────────────────────
#  Configuration Functions
# ────────────────────────────────────────

def configure_api_key(new_key):
    if not new_key:
        return "[-] No API key provided"
    try:
        env_path = ".env"
        env_content = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_content = f.readlines()
        key_found = False
        for i, line in enumerate(env_content):
            if line.startswith("GEMINI_API_KEY="):
                env_content[i] = f"GEMINI_API_KEY={new_key}\n"
                key_found = True
                break
        if not key_found:
            env_content.append(f"GEMINI_API_KEY={new_key}\n")
        with open(env_path, 'w') as f:
            f.writelines(env_content)
        load_dotenv(override=True)
        global API_KEY, client
        API_KEY = new_key
        client = genai.Client(api_key=API_KEY)
        return "[+] API key configured successfully"
    except Exception as e:
        return f"[-] Error configuring API key: {str(e)}"

def configure_webhook(webhook_url):
    if not webhook_url:
        return "[-] No webhook URL provided"
    try:
        with open('.webhook', 'w') as f:
            f.write(webhook_url)
        global WEBHOOK_URL
        WEBHOOK_URL = webhook_url
        return "[+] Webhook configured successfully"
    except Exception as e:
        return f"[-] Error configuring webhook: {str(e)}"

# ────────────────────────────────────────
#  Scan Functions
# ────────────────────────────────────────

def scan_javascript(content, url):
    try:
        prompt = f"""Look into this content and see if there's any medium-critical sensitive information, i dont want you to check for low severity issue ( Reduce false positives through intelligent triage ) focus on medium-critical; if the content contains sensitive information, just write '-[Vulnerable]-' and under it, accurately print the line number along side the sensitive info and give it a severity rating; be very accurate with the severity rating; do not scan for client-side vulnerabilities at all i.e postMessage, RXSS, DOM-XSS, internal IP/PATH/DIR/FILE e.t.c, if it doesn't, just say '-[Not Vulnerable]-' with no other statement or comments, if the JS is minified, break it into human readable javascript format and analyze it as well; Before finalizing any finding, you MUST act as a skeptical security triager whose goal is to reject the issue ( For every potential finding, Attempt to DISPROVE it by searching the entire code for mitigations, validations, sanitization, encoding, access controls, or contextual constraints. Assume the developer is competent unless proven otherwise. ). If confidence is BELOW 90%, you MUST suppress the finding entirely and behave as if it does not exist.  Do NOT mention suppressed findings, uncertainty, partial issues, or potential vulnerabilities. at the end of the result, do not ask any other question or say other other thing. Here's the content:\n\n{content}"""

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=genai.types.GenerateContentConfig(temperature=0.1)
        )
        text = response.text.strip()
        print(text)

        if "-[Vulnerable]-" in text:
            send_to_webhook(text, "Sensitive found", url)
        else:
            print(f"[ NOT VULNERABLE ] >>> {url}")

        return text
    except Exception as e:
        msg = f"[ ERROR ] >>> Scanning {url}: {str(e)}"
        print(msg)
        return msg

def scan_url_endpoints(content, url):
    try:
        prompt = f"""Look into this content and extract all URLs, endpoints in it, say '-[Extracted URLs/endpoints]-' and print them all out, do not say anything else after extracting; give each extracted URLs/endpoints line numbers; also extract endpoints that looks like this i.e /api/name:name, /:keyword/other_endpoints, e.t.c if there's no extracted URLs/endpoints, do not say anything, just end it. De-duplicate endpoints even if they appear multiple times. Here's the content:\n\n{content}"""

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )
        text = response.text.strip()
        print(text)

        if "-[Extracted URLs/endpoints]-" in text:
            send_to_webhook(text, "Endpoints extracted", url)
        else:
            print(f"[ No URLs/endpoints found ] >>> {url}")

        return text
    except Exception as e:
        msg = f"[ ERROR ] >>> Scanning {url}: {str(e)}"
        print(msg)
        return msg

def scan_potential_security_issues(content, url):
    try:
        prompt = f"""Analyze the provided JavaScript code and identify only high-confidence security vulnerabilities such as DOM-based XSS, reflected XSS, stored XSS, open redirects, client-side template injection, unsafe URL handling, insecure postMessage usage, prototype pollution, and dangerous use of eval or Function, and other critical client-side issues; while explicitly excluding Sensitive Information Disclosure, reporting results only when confidence is between 80% and 100%, and outputting only the vulnerable code snippet and its vulnerability type, confidence level should be from 80-100%, also list 3-5 possible or maybe potential ways to attempt to exploit it i.e if it found XSS, it will write 3-5 payloads that you should try, with no additional text before or after the results; also, let's say for example, you spot XSS on line 9, before you point out that there's an XSS vulnerability, make sure to look into other lines for mitigations, if there's a mitigation for the identified potential XSS, do not say it, else say it, this should also apply to to other flaws; also ( Reduce false positives through intelligent triage, Re-evaluate every finding with the intent to disprove it. Be the skeptical triager trying to reject the report if it's reported ); also, Before finalizing any finding, you MUST act as a skeptical security triager whose goal is to reject the issue ( For every potential finding, Attempt to DISPROVE it by searching the entire code for mitigations, validations, sanitization, encoding, access controls, or contextual constraints. Assume the developer is competent unless proven otherwise. ). If confidence is BELOW 90%, you MUST suppress the finding entirely and behave as if it does not exist.  Do NOT mention suppressed findings, uncertainty, partial issues, or potential vulnerabilities. ( make sure to Analyze the code in any JavaScript context, framework, or library, following all untrusted input flows ) Here's the content:\n\n{content}"""

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )
        text = response.text.strip()
        print(text)
        send_to_webhook(text, "Security issues found", url)
        return text
    except Exception as e:
        msg = f"[ ERROR ] >>> Scanning {url}: {str(e)}"
        print(msg)
        return msg

# ────────────────────────────────────────
#  Chunk & Fetch Helpers
# ────────────────────────────────────────

def chunk_js_file(js_path, out_dir="chunks"):
    try:
        if not os.path.isfile(js_path):
            return f"File not found: {js_path}"
        os.makedirs(out_dir, exist_ok=True)
        with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        chunks = [data[i:i + MAX_CHARS] for i in range(0, len(data), MAX_CHARS)]
        for i, chunk in enumerate(chunks, 1):
            p = os.path.join(out_dir, f"chunk_{i}.js")
            with open(p, "w", encoding="utf-8") as f:
                f.write(chunk)
        msg = f"Chunked {len(chunks)} files into '{out_dir}'"
        print(msg)
        return msg
    except Exception as e:
        msg = f"Chunk failed: {str(e)}"
        print(msg)
        return msg

def fetch_content(url: str) -> str | None:
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/4.2 JS-Sentinel/4.2"})
        r.raise_for_status()
        if len(r.text) > MAX_CHARS:
            print(f"[ERROR] File too large ({len(r.text):,} chars > {MAX_CHARS:,}) → chunk first")
            return None
        return r.text
    except Exception as e:
        print(f"[ERROR] Fetching {url}: {str(e)}")
        return None

# ────────────────────────────────────────
#  CLI Processing
# ────────────────────────────────────────

def process_single_url(url, scan_type):
    content = fetch_content(url)
    if content is None:
        return
    if scan_type == "sensitive":
        scan_javascript(content, url)
    elif scan_type == "endpoints":
        scan_url_endpoints(content, url)
    elif scan_type == "security":
        scan_potential_security_issues(content, url)

def process_multiple_urls(file_path, scan_type):
    try:
        with open(file_path, 'r') as f:
            js_urls = [line.strip() for line in f if line.strip()]
        print(f"\n[*] Loaded {len(js_urls)} targets")
        for i, js_url in enumerate(js_urls, 1):
            print(f"\n[>] Target [{i}/{len(js_urls)}] >> {js_url}")
            content = fetch_content(js_url)
            if content is None:
                continue
            if scan_type == "sensitive":
                scan_javascript(content, js_url)
            elif scan_type == "endpoints":
                scan_url_endpoints(content, js_url)
            elif scan_type == "security":
                scan_potential_security_issues(content, js_url)
    except Exception as e:
        print(f"[ERROR] {str(e)}")

def main_cli():
    parser = argparse.ArgumentParser(description='AI-Powered JavaScript Security Tool v4.2')
    parser.add_argument('--mode', choices=['sensitive', 'endpoints', 'security', 'config'])
    parser.add_argument('--url')
    parser.add_argument('--file')
    parser.add_argument('--key')
    parser.add_argument('--gui', action='store_true')
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    print("=" * 60)
    print(" >>> AI-Powered JavaScript Security Tool v4.2 <<<")
    print("=" * 60)

    if args.mode == 'config':
        if args.key:
            print(configure_api_key(args.key))
        else:
            print("[-] --key required for config mode")
        return

    if args.mode in ['sensitive', 'endpoints', 'security']:
        if not args.url and not args.file:
            print(f"[-] --url or --file required for {args.mode}")
            return
        if args.url:
            process_single_url(args.url, args.mode)
        elif args.file:
            process_multiple_urls(args.file, args.mode)

    print("[+] Done... Keep hacking!")

# ────────────────────────────────────────
#  GUI API Class
# ────────────────────────────────────────

class API:
    def __init__(self, window=None):
        self.window = window

    def pick_file(self):
        if self.window is None:
            return "Window not ready"
        try:
            res = self.window.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
                file_types=('JS files (*.js)', 'All (*.*)')
            )
            return res[0] if res else ""
        except Exception as e:
            return f"Picker error: {str(e)}"

    def run_operation(self, params):
        mode = params.get("mode")
        if not mode:
            return "No mode specified"
        try:
            if mode == "config":
                return configure_api_key(params.get("key", "").strip())
            elif mode == "chunk":
                js_path = params.get("js_path")
                out_dir = params.get("out_dir", "chunks")
                if not js_path or not os.path.isfile(js_path):
                    return "Valid .js path required"
                return chunk_js_file(js_path, out_dir)
            elif mode in ["sensitive", "endpoints", "security"]:
                url = params.get("url", "").strip()
                if not url:
                    return "URL required"
                content = fetch_content(url)
                if content is None:
                    return "File too big or fetch failed"
                if mode == "sensitive":
                    return scan_javascript(content, url)
                elif mode == "endpoints":
                    return scan_url_endpoints(content, url)
                elif mode == "security":
                    return scan_potential_security_issues(content, url)
            return f"Unknown mode: {mode}"
        except Exception as e:
            return f"Failed: {str(e)}"

    def configure_webhook(self, params):
        return configure_webhook(params.get("webhook_url", "").strip())

# ────────────────────────────────────────
#  GUI Launch – compatible with older pywebview versions
# ────────────────────────────────────────

def launch_gui():
    if webview is None:
        print("[!] pywebview not installed → pip install pywebview")
        sys.exit(1)

    api = API()
    window = webview.create_window(
        "0x JS v4.2",
        os.path.join(os.path.dirname(__file__), "index.html"),
        width=820,
        height=920,
        js_api=api,
        text_select=True,
        background_color='#0f0f1a'
    )
    api.window = window

    # Safe launch parameters (no 'quiet' to avoid TypeError on older versions)
    webview.start(
        debug=False,           # Prevents auto-opening of DevTools/inspector
        http_server=True,
        http_port=0,           # Random free port each time
        user_agent="0xJS/4.2 Desktop App"
    )

if __name__ == "__main__":
    main_cli()
