import sys
from datetime import datetime
import os
import ssl
import socket
from urllib.parse import urlparse
import OpenSSL.crypto

def extract_domain(input_string):
    """Extract domain from URL or return the domain if already provided."""
    try:
        parsed = urlparse(input_string)
        # If no scheme provided, add https:// and try again
        if not parsed.netloc:
            parsed = urlparse(f"https://{input_string}")
        return parsed.netloc or input_string.split(':')[0]
    except Exception:
        return input_string

def check_ssl_cert(domain):
    """Check SSL certificate details for the given domain."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Get certificate details
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                # Calculate days until expiration
                days_to_expire = (not_after - datetime.now()).days
                
                print("\n[*] Certificate Details:")
                print(f"[*] Domain: {domain}")
                print(f"[*] Issuer: {issuer.get('organizationName', 'N/A')}")
                print(f"[*] Organization: {subject.get('organizationName', 'N/A')}")
                print(f"[*] Valid From: {not_before.strftime('%Y-%m-%d')}")
                print(f"[*] Valid Until: {not_after.strftime('%Y-%m-%d')}")
                print(f"[*] Days Until Expiration: {days_to_expire}")
                
                # Warning if certificate is expiring soon
                if days_to_expire <= 30:
                    print(f"[!] WARNING: Certificate expires in {days_to_expire} days!", file=sys.stderr)
                
                return True
                
    except ssl.SSLError as e:
        print(f"[!] SSL Error: {str(e)}", file=sys.stderr)
        return False
    except socket.gaierror:
        print(f"[!] Error: Could not resolve domain {domain}", file=sys.stderr)
        return False
    except socket.timeout:
        print(f"[!] Error: Connection timed out", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        return False

def main():
    if len(sys.argv) != 2:
        print("[!] Error: Please provide a domain or URL as an argument", file=sys.stderr)
        print("[*] Usage: python app.py example.com")
        print("[*] Usage: python app.py https://example.com")
        sys.exit(1)
    
    input_string = sys.argv[1]
    domain = extract_domain(input_string)
    
    print(f"[*] Checking TLS/SSL certificate for: {domain}")
    check_ssl_cert(domain)

if __name__ == "__main__":
    main()
