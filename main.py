import os
from dotenv import load_dotenv
from google import genai
import requests
import sys

load_dotenv()

if os.name == "unix":
    os.system('clear')
else:
    os.system('cls')

def configure_api_key():
    """Configure or update the GEMINI_API_KEY in .env file"""
    print("\n" + "=" * 60)
    print(" API KEY CONFIGURATION")
    print("=" * 60)
    
    current_key = os.getenv("GEMINI_API_KEY")
    if current_key:
        print(f"Current API key: {current_key[:5]}...{current_key[-5:] if len(current_key) > 10 else ''}")
    
    new_key = input("Enter new GEMINI API key: ").strip()
    
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
    """Get API key from environment or prompt for configuration"""
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("\n[!] GEMINI_API_KEY not found in .env")
        configure = input("Would you like to configure it now? (y/n): ").strip().lower()
        
        if configure == 'y':
            api_key = configure_api_key()
            if not api_key:
                print("[-] Exiting due to missing API key")
                exit()
        else:
            print("[-] Exiting - API key required")
            exit()
    
    return api_key

def scan_javascript(content, url):
    try:
        api_key = get_api_key()
        client = genai.Client(api_key=api_key)
        
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=f"Look into this content and see if there's any medium-critical sensitive information, i dont want you to check for low severity issue, focus on medium-critical; if the content contains sensitive information, just write '-[Vulnerable]-' and under it, accurately print the line number along side the sensitive info and give it a severity rating; be very accurate with the severity rating, if it doesn't, just say '-[Not Vulnerable]-' with no other statement or comments, if the JS is minified, break it into human readable javascript format and analyze it as well; at the end of the result, do not ask any other question or say other other thing. Here's the content  {content}"
        )
        print()
        if "-[Vulnerable]-" in response.text:
            print(response.text)
            print("-" * 60)
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
            contents=f"Analyze the provided JavaScript code and identify only high-confidence security vulnerabilities such as DOM-based XSS, reflected XSS, stored XSS, open redirects, client-side template injection, unsafe URL handling, insecure postMessage usage, prototype pollution, and dangerous use of eval or Function, while explicitly excluding Sensitive Information Disclosure, reporting results only when confidence is between 80% and 100%, and outputting only the vulnerable code snippet and its vulnerability type with no additional text before or after the results. Here's the content  {content}"
        )
        print()
        print(response.text)
        print("-" * 60)
        
            
    except Exception as e:
        print(f"[ ERROR ] >>> Scanning {url}: {str(e)}")

def main():
    print()
    print("=" * 60)
    print("  >>> AI-Powered JavaScript Security Tool v3.0 <<<")
    print("=" * 60)
    print("\n[1] Scan Single JavaScript URL ( Sensitive Informations )")
    print("[2] Scan Multiple JavaScript URLs from File ( Sensitive Informations )")
    print("[3] Extract URLs/endpoints")
    print("[4] Scan For Potential Security Issues In JS ( i.e DOM-XSS, open redirect, e.t.c )")
    print("[5] Configure API Key")
    print("[6] Exit")
    print("=" * 60)
    
    choice = input("\n>> ").strip()
    
    if choice == "1":
        print("=" * 60)
        print("  >>> SINGLE TARGET SCAN <<<")
        print("=" * 60)
        url = input("\n[?] URL >> ").strip()
        if len(requests.get(url).text) <= 800000:
            pass
        else:
            print("\n[ERROR] JS file too large for analysis. Maximum allowed size - 800,000 characters. Provided size",len(requests.get(url).text),"characters. Split the JavaScript into smaller chunks using ./chunk.py, host them locally, and try again.\n")
            exit()
        try:
            print(f"\n[*] Fetching target >> {url}")
            get_c = requests.get(url).text
            scan_javascript(get_c, url)
        except Exception as e:
            print(f"\n [ERROR] Fetching {url} >> {str(e)}")
            
    elif choice == "3":
        print("=" * 60)
        print("  >>> Extract URLs/endpoints <<<")
        print("=" * 60)
        url = input("\n[?] URL >> ").strip()
        if len(requests.get(url).text) <= 800000:
            pass
        else:
            print("\n[ERROR] JS file too large for analysis. Maximum allowed size - 800,000 characters. Provided size",len(requests.get(url).text),"characters. Split the JavaScript into smaller chunks using ./chunk.py, host them locally, and try again.\n")
            exit()
        try:
            print(f"\n[*] Fetching target >> {url}")
            get_c = requests.get(url).text
            scan_url_endpoints(get_c, url)
        except Exception as e:
            print(f"\n [ERROR] Fetching {url} >> {str(e)}")

    elif choice == "4":
        print("=" * 60)
        print("  >>> Scan For Potential Security Issues In JS <<<")
        print("=" * 60)
        url = input("\n[?] URL >> ").strip()
        if len(requests.get(url).text) <= 800000:
            pass
        else:
            print("\n[ERROR] JS file too large for analysis. Maximum allowed size - 800,000 characters. Provided size",len(requests.get(url).text),"characters. Split the JavaScript into smaller chunks using ./chunk.py, host them locally, and try again.\n")
            exit()
        try:
            print(f"\n[*] Fetching target >> {url}")
            get_c = requests.get(url).text
            scan_potential_security_issues(get_c, url)
        except Exception as e:
            print(f"\n [ERROR] Fetching {url} >> {str(e)}")

    elif choice == "5":
        print("=" * 60)
        print("  >>> Configure API Key <<<")
        print("=" * 60)
        key = input("\n[?] KEY >> ").strip()
        f = open('.env', 'w').write("GEMINI_API_KEY="+key)

    elif choice == "2":
        print("=" * 60)
        print("  MULTIPLE TARGET SCAN")
        print("=" * 60)
        file_path = input("\n[?] Path to target list >> ").strip()
        try:
            with open(file_path, 'r') as f:
                js_urls = [line.strip() for line in f if line.strip()]
            
            print(f"\n[*] Loaded {len(js_urls)} targets for scanning")
            print("[*] Initializing attack vector...")
            print("-" * 60)
            
            for i, js_url in enumerate(js_urls, 1):
                try:
                    print(f"\n[>] Target [{i}/{len(js_urls)}] >> {js_url}")
                    if len(requests.get(js_url).text) <= 800000:
                      pass
                    else:
                        print("\n[ERROR] JS file too large for analysis. Maximum allowed size - 800,000 characters. Provided size",len(requests.get(js_url).text),"characters. Split the JavaScript into smaller chunks using ./chunk.py, host them locally, and try again.\n")
                        exit()
                    get_c = requests.get(js_url).text
                    scan_javascript(get_c, js_url)
                except Exception as e:
                    print(f"\n[ERROR] Fetching {js_url} >> {str(e)}")
                    
        except FileNotFoundError:
            print(f"\n[ERROR] Target list not found >> {file_path}")
        except Exception as e:
            print(f"\n[ERROR] Reading target list >> {str(e)}")
    

    
    elif choice == "6":
        print("\n" + "=" * 60)
        print("[+] Exiting...")
        print("[+] System shutdown complete")
        print("=" * 60)
        sys.exit(0)
        
    else:
        print("\n[!] Invalid option. Choose 1-6.")
    
    print("\n" + "=" * 60)
    print("[+] Done...")
    print("[+] Keep hacking the mainframe")
    print("=" * 60)
    print()

if __name__ == "__main__":
    main()
