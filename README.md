# Aegis - Security Assistant
Aegis is a lightweight security assistant designed to help you analyze websites for common vulnerabilities such as SSL certificate issues, missing HTTP security headers, and potential phishing threats. This tool provides a clear and friendly user experience with step-by-step guidance and explanations for each security check. Perfect for web administrators, security enthusiasts, and anyone concerned with online safety.

## Feature
SSL Certificate Validation: Checks if the SSL certificate is valid and properly configured.`
HTTP Security Headers Check: Verifies important security headers like X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, and more.
Phishing Detection: Analyzes URLs for common patterns associated with phishing attacks.
System Information: Displays basic system info, including internal and external IP addresses, to give context to the checks.


## Installation 
### Prerequisites
Python 3.6+ is required.
The following Python libraries need to be installed:
requests
validators
platform (part of Python's standard library)
socket (part of Python's standard library)

#### Clone the repository
`git clone https://github.com/Fujimori-Zeta/Aegis.git`
`cd Aegis`
#### Install Dependencies
You can install the required dependencies using pip:
`pip install -r requirements.txt`


## Usage

### Running the Program
To run Aegis, simply execute the Python script in your terminal. The script will guide you through a series of checks for the website you want to analyze.
`python3 aegis.py`
You will be prompted to enter a URL:
`Enter the URL you want to check: https://example.com`

Aegis will then proceed to check the website for the following:
- SSL Certificate Status
- HTTP Security Headers
- Phishing Indicators
After completing the checks, it will provide a report showing any detected issues or confirming that the website is secure.
#### Example output

`=================`
       `Aegis`       
  
   Created by Fujimori-Zeta
`==================`

`System Information:` 
`Your system is running Linux 5.4.0-74-generic (64bit)`
`Hostname: my-computer`
`Local IP Address: 192.168.1.5`
`External IP Address: 203.0.113.10`

Starting security checks for the domain: https://example.com...
Don't worry, this might take a minute...

SSL Certificate Check:
Great! The SSL Certificate is valid and secure.

HTTP Headers Security Check:
Perfect! All security headers are properly configured.

Phishing URL Analysis:
All good! No phishing indicators found in this URL.

`===================================`
Everything looks great! No issues detected on the domain.
`===================================`

## Features & Detailed Checks
### SSL Certificate Check
This check verifies that the site is using HTTPS with a valid SSL certificate. If there's a problem with the SSL certificate, such as it being expired or improperly configured, the program will notify you.

### HTTP Security Headers
Aegis checks for important HTTP security headers that help protect against attacks like cross-site scripting (XSS), clickjacking, and content sniffing. It will flag any missing or improperly configured headers such as:

- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Content-Security-Policy
- Access-Control-Allow-Origin

## Phishing Detection
Aegis performs a basic phishing URL analysis by looking for common patterns that are typically found in phishing sites, such as login, secure, account, etc. If such patterns are detected, the URL will be flagged.


## Contributing
Contributions are welcome! If you'd like to contribute to Aegis, feel free to fork the repository, make improvements, and create a pull request.

#### How to Contribute
Fork the repository on GitHub.
Create a new branch (git checkout -b feature/your-feature).
Make your changes and commit them (git commit -am 'Add new feature').
Push your changes (git push origin feature/your-feature).
Create a pull request.

## Bug Reports & Feature Requests
If you encounter any bugs or have suggestions for new features, please open an issue on GitHub. Be sure to provide as much detail as possible, including any relevant error messages or logs.

