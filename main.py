import os
from dotenv import load_dotenv
from google import genai
import requests
import sys
import argparse

load_dotenv()

if os.name == "unix":
    os.system('clear')
else:
    os.system('cls')

def configure_api_key(new_key):
    """Configure or update the GEMINI_API_KEY in .env file"""
    if new_key:
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
            
            # Write back to .env
            with open(env_path, 'w') as f:
                f.writelines(env_content)
            
            print("[+] API key configured successfully")
            
            # Reload environment variables
            load_dotenv(override=True)
            return new_key
            
        except Exception as e:
            print(f"[-] Error configuring API key: {str(e)}")
            return None
    else:
        print("[-] No API key provided")
        return None

def get_api_key():
    """Get API key from environment"""
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("[-] Exiting - GEMINI_API_KEY not found in .env")
        sys.exit(1)
    
    return api_key

def scan_javascript(content, url):
    try:
        api_key = get_api_key()
        client = genai.Client(api_key=api_key)
        
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=f"Look into this content and see if there's any medium-critical sensitive information, i dont want you to check for low severity issue, focus on medium-critical; if the content contains sensitive information, just write '-[Vulnerable]-' and under it, accurately print the line number along side the sensitive info and give it a severity rating; be very accurate with the severity rating; do not scan for client-side vulnerabilities at all i.e postMessage, RXSS, DOM-XSS, internal IP/PATH/DIR/FILE e.t.c, if it doesn't, just say '-[Not Vulnerable]-' with no other statement or comments, if the JS is minified, break it into human readable javascript format and analyze it as well; at the end of the result, do not ask any other question or say other other thing. Here's the content  {content}"
        )
        print()
        if "-[Vulnerable]-" in response.text:
            print(response.text)
            print("-" * 60)
            webhook_url = open('.webhook', 'r').read()
            try:
                requests.post(webhook_url, json={"content": response.text})
            except:
                print("[ ERROR ] >>> Unable to send result to discord; check your configuration in .webhook ")
                print()
                exit()

        else:
            print(f"[ NOT VULNERABLE ] >>> {url}")
            
    except Exception as e:
        print(f"[ ERROR ] >>> Scanning {url}: {str(e)}")

def scan_url_endpoints(content, url):
    try:
        api_key = get_api_key()
        client = genai.Client(api_key=api_key)
        
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=f"Look into this content and extract all URLs, endpoints in it, say '-[Extracted URLs/endpoints]-' and print them all out, do not say anything else after extracting; give each extracted URLs/endpoints line numbers; if there's no extracted URLs/endpoints, do not say anything, just end it. Here's the content  {content}"
        )
        print()
        if "-[Extracted URLs/endpoints]-" in response.text:
            print(response.text)
            print("-" * 60)
            webhook_url = open('.webhook', 'r').read()
            try:
                requests.post(webhook_url, json={"content": response.text})
            except:
                print("[ ERROR ] >>> Unable to send result to discord; check your configuration in .webhook ")
                print()
                exit()
        else:
            print(f"[ No URLs/endpoints found ] >>> {url}")
            
    except Exception as e:
        print(f"[ ERROR ] >>> Scanning {url}: {str(e)}")

def scan_potential_security_issues(content, url):
    try:
        api_key = get_api_key()
        client = genai.Client(api_key=api_key)
        
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=f"Analyze the provided JavaScript code and identify only high-confidence security vulnerabilities such as DOM-based XSS, reflected XSS, stored XSS, open redirects, client-side template injection, unsafe URL handling, insecure postMessage usage, prototype pollution, and dangerous use of eval or Function, and other critical client-side issues; while explicitly excluding Sensitive Information Disclosure, reporting results only when confidence is between 80% and 100%, and outputting only the vulnerable code snippet and its vulnerability type with no additional text before or after the results; also, let's say for example, you spot XSS on line 9, before you point out that there's an XSS vulnerability, make sure to look into other lines for mitigations, if there's a mitigation for the identified potential XSS, do not say it, else say it, this should also apply to to other flaws. Here's the content  {content}"
        )
        print()
        print(response.text)
        print("-" * 60)
        webhook_url = open('.webhook', 'r').read()
        try:
            requests.post(webhook_url, json={"content": response.text})
        except:
            print("[ ERROR ] >>> Unable to send result to discord; check your configuration in .webhook ")
            print()
            exit()
        
    except Exception as e:
        print(f"[ ERROR ] >>> Scanning {url}: {str(e)}")

def process_single_url(url, scan_type):
    """Process a single URL with the specified scan type"""
    try:
        print(f"\n[*] Fetching target >> {url}")
        response = requests.get(url)
        content_length = len(response.text)
        
        if content_length > 800000:
            print(f"\n[ERROR] JS file too large for analysis. Maximum allowed size - 800,000 characters. Provided size {content_length} characters. Split the JavaScript into smaller chunks using ./chunk.py, host them locally, and try again.\n")
            return
        
        if scan_type == "sensitive":
            scan_javascript(response.text, url)
        elif scan_type == "endpoints":
            scan_url_endpoints(response.text, url)
        elif scan_type == "security":
            scan_potential_security_issues(response.text, url)
            
    except Exception as e:
        print(f"\n [ERROR] Fetching {url} >> {str(e)}")

def process_multiple_urls(file_path, scan_type):
    """Process multiple URLs from a file with the specified scan type"""
    try:
        with open(file_path, 'r') as f:
            js_urls = [line.strip() for line in f if line.strip()]
        
        print(f"\n[*] Loaded {len(js_urls)} targets for scanning")
        print("[*] Initializing attack vector...")
        print("-" * 60)
        
        for i, js_url in enumerate(js_urls, 1):
            try:
                print(f"\n[>] Target [{i}/{len(js_urls)}] >> {js_url}")
                response = requests.get(js_url)
                content_length = len(response.text)
                
                if content_length > 800000:
                    print(f"\n[ERROR] JS file too large for analysis. Maximum allowed size - 800,000 characters. Provided size {content_length} characters. Split the JavaScript into smaller chunks using ./chunk.py, host them locally, and try again.\n")
                    continue
                
                if scan_type == "sensitive":
                    scan_javascript(response.text, js_url)
                elif scan_type == "endpoints":
                    scan_url_endpoints(response.text, js_url)
                elif scan_type == "security":
                    scan_potential_security_issues(response.text, js_url)
                    
            except Exception as e:
                print(f"\n[ERROR] Fetching {js_url} >> {str(e)}")
                
    except FileNotFoundError:
        print(f"\n[ERROR] Target list not found >> {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Reading target list >> {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='AI-Powered JavaScript Security Tool v4.0')
    parser.add_argument('--mode', choices=['sensitive', 'endpoints', 'security', 'config'], 
                       required=True, help='Scan mode')
    parser.add_argument('--url', help='Single URL to scan')
    parser.add_argument('--file', help='File containing list of URLs to scan')
    parser.add_argument('--key', help='Configure API key')
    
    args = parser.parse_args()
    
    print()
    print("=" * 60)
    print("  >>> AI-Powered JavaScript Security Tool v4.0 <<<")
    print("=" * 60)
    
    # Handle API key configuration
    if args.mode == 'config':
        if args.key:
            configure_api_key(args.key)
            print("\n" + "=" * 60)
            print("[+] Done...")
            print("[+] Keep hacking the mainframe")
            print("=" * 60)
            print()
            return
        else:
            print("[-] Error: --key argument required for config mode")
            sys.exit(1)
    
    # Validate scan modes have required arguments
    if args.mode in ['sensitive', 'endpoints', 'security']:
        if not args.url and not args.file:
            print(f"[-] Error: Either --url or --file required for {args.mode} mode")
            sys.exit(1)
        
        if args.url and args.file:
            print("[-] Error: Please specify either --url or --file, not both")
            sys.exit(1)
        
        # Process single URL
        if args.url:
            process_single_url(args.url, args.mode)
        
        # Process multiple URLs from file
        elif args.file:
            process_multiple_urls(args.file, args.mode)
    
    print("\n" + "=" * 60)
    print("[+] Done...")
    print("[+] Keep hacking the mainframe")
    print("=" * 60)
    print()

if __name__ == "__main__":
    main()




