import os
import requests
import platform
import socket
import validators
import logging
import time

# Colors for console output
RED = '\033[91m]'
GREEN = '\033[92m]'
BLUE = '\033[94m]'
CYAN = '\033[96m]'
RESET = '\033[0m]'

# Set up logging for debugging purposes
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def clear_terminal():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Display a friendly banner."""
    print(f"{GREEN}====================")
    print(f"            Aegis          ")
    print(f"   Created by Fujimori-Zeta")
    print(f"==================\n{RESET}")

def get_system_info():
    """Retrieve system information, including external IP."""
    system = platform.system()
    version = platform.version()
    architecture = platform.architecture()
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    # Get external IP
    try:
        external_ip = requests.get('https://api.ipify.org').text
    except requests.exceptions.RequestException:
        external_ip = "Unable to retrieve external IP."

    return (f"Your system is running {system} {version} ({architecture[0]})\n"
            f"Hostname: {hostname}\n"
            f"Local IP Address: {ip_address}\n"
            f"External IP Address: {external_ip}")

def validate_url(url):
    """Validate and format the URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not validators.url(url):
        print(f"{RED}Not a valid URL. Please check and try again.{RESET}")
        return None
    return url

def check_ssl_certificate(url, session):
    """Check if the SSL certificate is valid."""
    print(f"\n{CYAN}Checking SSL Certificate...{RESET}")
    try:
        response = session.get(url, verify=True)
        print(f"{GREEN}Great! The SSL Certificate is valid and secure.{RESET}")
        return True
    except requests.exceptions.SSLError:
        print(f"{RED}Hmm... It looks like there's an issue with the SSL Certificate. It might be expired or not valid.{RESET}")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"{RED}Oops, there was a connection error: {e}. Please check if the URL is correct and try again.{RESET}")
        return False
    except Exception as e:
        print(f"{RED}Something unexpected happened: {e}. Please try again later.{RESET}")
        return False

def check_http_headers(url, session):
    """Check for security headers and potential vulnerabilities."""
    print(f"\n{CYAN}Analyzing HTTP Security Headers...{RESET}")
    try:
        response = session.get(url)
        issues_found = False

        # Security headers to check with basic vulnerability analysis
        header_checks = {
            "X-Content-Type-Options": {
                "expected_value": "nosniff",
                "vulnerability": "Missing or incorrect X-Content-Type-Options; may allow MIME-type sniffing."
            },
            "X-Frame-Options": {
                "expected_value": ["DENY", "SAMEORIGIN"],
                "vulnerability": "X-Frame-Options may be vulnerable to clickjacking attacks."
            },
            "X-XSS-Protection": {
                "expected_value": "1; mode=block",
                "vulnerability": "X-XSS-Protection is missing or not set to block mode; may allow cross-site scripting attacks."
            },
            "Content-Security-Policy": {
                "expected_value": None,
                "vulnerability": "Content-Security-Policy is missing; may allow various attacks, including XSS."
            },
            "Access-Control-Allow-Origin": {
                "expected_value": None,
                "vulnerability": "Improper CORS configuration may expose the site to cross-origin attacks."
            }
        }

        for header, check in header_checks.items():
            if header not in response.headers:
                print(f"{RED}Uh-oh, {header} is missing! {check['vulnerability']}{RESET}")
                issues_found = True
            else:
                header_value = response.headers[header]
                expected_value = check["expected_value"]

                if expected_value and header_value not in (expected_value if isinstance(expected_value, list) else [expected_value]):
                    print(f"{RED}Oops, {header} is present, but the value '{header_value}' might still pose a security risk. {check['vulnerability']}{RESET}")
                    issues_found = True

        if not issues_found:
            print(f"{GREEN}Perfect! All security headers are properly configured.{RESET}")
        return not issues_found

    except requests.exceptions.RequestException as e:
        print(f"{RED}Sorry, we couldn't check the headers due to: {e}. Please try again later.{RESET}")
        return False

def check_phishing(url):
    """Basic phishing detection based on URL patterns."""
    print(f"\n{CYAN}Running Phishing URL Analysis...{RESET}")
    phishing_patterns = [
        "account", "login", "secure", "bank", "update", "confirm", "verify", "expired",
        "password", "admin", "signin", "auth", "validate", "unlock", "urgent", "important", 
        "alert", "suspended", "limited", "notice", "access", "recovery", "customer-service", 
        "support", "webmail", "email", "mailbox", "new-message", "messages", "helpdesk", 
        "billing", "payment", "checkout", "invoice", "account-pay", "paypal", "credit", 
        "transfer", "transaction", "secure-login", "auth", "signin", "account-update",
        "-secure-", "-login-", "verify"
    ]

    # Convert the URL to lowercase for case-insensitive matching
    url_lower = url.lower()

    if any(pattern in url_lower for pattern in phishing_patterns):
        print(f"{RED}Warning! This URL contains suspicious patterns that may indicate a phishing site.{RESET}")
        return False

    print(f"{GREEN}No phishing indicators found in this URL.{RESET}")
    return True

def setup_session():
    """Sets up a session for HTTP requests with a custom User-Agent."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Aegis"
    })
    return session

def main(url):
    """Main function to run all security checks."""
    clear_terminal()
    display_banner()

    print(f"{BLUE}Let's check the system details before we begin:{RESET}")
    print(get_system_info())
    print(f"\n{BLUE}Starting security checks for the domain: {url}...{RESET}")
    print(f"Don't worry, this might take a minute...")

    # validates the URL before proceeding
    valid_url = validate_url(url)
    if valid_url is None:
        print(f"{RED}Please provide a valid URL so we can continue.{RESET}")
        return  # Exit if the URL is invalid

    session = setup_session()

    # runs the security checks
    ssl_check = check_ssl_certificate(valid_url, session)
    header_check = check_http_headers(valid_url, session)
    phishing_check = check_phishing(valid_url)

    print("\n" + "=" * 35)
    if not (ssl_check and header_check and phishing_check):
        print(f"{RED}⚠️ Issues were detected! Please review the warnings above.{RESET}")
        print(f"{RED}It’s highly recommended that you address these security concerns.{RESET}")
    else:
        print(f"{GREEN}Everything looks great! No issues detected on the domain.{RESET}")
    print("=" * 35 + "\n")

if __name__ == "__main__":
    try:
        test_url = input("Enter the URL you want to check: ").strip()
        print(f"\nThanks for using Aegis! Let's get started...")
        time.sleep(1)  # simulates a brief wait before starting
        main(test_url)
    except KeyboardInterrupt:
        print("\n[INFO] You’ve interrupted the program. Have a nice day!")
    except Exception as e:
        logging.error(f"Something went wrong: {e}")
        print(f"{RED}Something went wrong. Please try again later.{RESET}")
