import requests
import argparse
import sys
import os

# --- Visuals ---
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def evaluate_site(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"{CYAN}[*] Initializing Advanced Scan on: {url}{RESET}")
    print("-" * 65)

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        print(f"{RED}[-] Connection Failure: {e}{RESET}")
        sys.exit(1)

    score = 100
    total_headers = 5
    deduction = 20  # Lose 20 points per missing security header

    # 1. Server Leak Analysis
    print(f"\n{BOLD}[ Phase 1: Information Disclosure ]{RESET}")
    leaks = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
    found_leaks = 0
    for leak in leaks:
        if leak in headers:
            print(f" {RED}!{RESET} {leak:<18} : {YELLOW}{headers[leak]}{RESET}")
            found_leaks += 1
    if found_leaks == 0:
        print(f" {GREEN}+{RESET} No obvious framework or server software leaks detected.")
    else:
        score -= (found_leaks * 5) # Minor penalty for leaking software names

    # 2. Deeper Security Header Logic
    print(f"\n{BOLD}[ Phase 2: Security Header Matrix ]{RESET}")

    # HSTS Check
    if "Strict-Transport-Security" in headers:
        print(f" {GREEN}[+] {RESET}Strict-Transport-Security is {GREEN}ACTIVE{RESET}")
    else:
        print(f" {RED}[-] {RESET}Strict-Transport-Security is {RED}MISSING{RESET} -> Vulnerable to SSL Stripping!")
        score -= deduction

    # CSP Check
    if "Content-Security-Policy" in headers:
        print(f" {GREEN}[+] {RESET}Content-Security-Policy is {GREEN}ACTIVE{RESET}")
    else:
        print(f" {RED}[-] {RESET}Content-Security-Policy is {RED}MISSING{RESET} -> Vulnerable to XSS injection!")
        score -= deduction

    # X-Frame-Options Check
    if "X-Frame-Options" in headers:
        val = headers["X-Frame-Options"].upper()
        if "DENY" in val or "SAMEORIGIN" in val:
            print(f" {GREEN}[+] {RESET}X-Frame-Options is {GREEN}ACTIVE{RESET} ({val})")
        else:
            print(f" {YELLOW}[!] {RESET}X-Frame-Options is {YELLOW}WEAK{RESET} ({val}) -> Risk of Clickjacking.")
            score -= 10
    else:
        print(f" {RED}[-] {RESET}X-Frame-Options is {RED}MISSING{RESET} -> High risk of Clickjacking!")
        score -= deduction

    # X-Content-Type Check
    if "X-Content-Type-Options" in headers:
        if "nosniff" in headers["X-Content-Type-Options"].lower():
            print(f" {GREEN}[+] {RESET}X-Content-Type-Options is {GREEN}ACTIVE{RESET}")
        else:
            print(f" {YELLOW}[!] {RESET}X-Content-Type-Options is {YELLOW}MALCONFIGURED{RESET}")
            score -= 10
    else:
        print(f" {RED}[-] {RESET}X-Content-Type-Options is {RED}MISSING{RESET} -> Risk of MIME-sniffing exploits.")
        score -= deduction

    # Referrer-Policy Check
    if "Referrer-Policy" in headers:
        print(f" {GREEN}[+] {RESET}Referrer-Policy is {GREEN}ACTIVE{RESET}")
    else:
        print(f" {RED}[-] {RESET}Referrer-Policy is {RED}MISSING{RESET} -> Leaks internal user navigation URLs.")
        score -= deduction

    # 3. Final Scoring and Grading Engine
    score = max(0, score) # Don't allow negative scores

    if score >= 90: grade = f"{GREEN}A{RESET}"
    elif score >= 80: grade = f"{GREEN}B{RESET}"
    elif score >= 70: grade = f"{YELLOW}C{RESET}"
    elif score >= 60: grade = f"{YELLOW}D{RESET}"
    else: grade = f"{RED}F (Vulnerable){RESET}"

    print("\n" + "=" * 65)
    print(f"{BOLD}FINAL SECURITY SCORE: {score}/100   |   GRADE: {grade}{RESET}")
    print("=" * 65 + "\n")


def main():
    os.system('') # Windows ANSI Colors Fix
    parser = argparse.ArgumentParser(description="Pro-Grade HTTP Security Configuration Auditor")
    parser.add_argument("-u", "--url", type=str, required=True, help="Target host domain/URL")
    args = parser.parse_args()
    evaluate_site(args.url)

if __name__ == "__main__":
    main()