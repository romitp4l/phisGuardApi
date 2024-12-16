import requests
from urllib.parse import urlparse
import tldextract
import whois
import socket
import re
from bs4 import BeautifulSoup
import ipaddress
import dns.resolver
import datetime  # Import datetime

def analyze_url(url):
    report = {}

    try:
        # 1. Basic URL Information
        parsed_url = urlparse(url)
        report['url'] = url
        report['scheme'] = parsed_url.scheme
        report['netloc'] = parsed_url.netloc
        report['path'] = parsed_url.path
        report['query'] = parsed_url.query

        # 2. Domain Information
        extracted = tldextract.extract(url)
        report['subdomain'] = extracted.subdomain
        report['domain'] = extracted.domain
        report['suffix'] = extracted.suffix

        try:
            w = whois.whois(url)
            report['whois'] = w
        except Exception as e:
            report['whois_error'] = str(e)

        try:
            ip_address = socket.gethostbyname(parsed_url.netloc)
            report['ip_address'] = ip_address
        except socket.gaierror:
            report['ip_address'] = "Could not resolve hostname"

        # 3. URL Features (Indicators of Phishing)
        report['length'] = len(url)
        report['has_@'] = "@" in url
        report['has_ip_address'] = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) is not None
        report['shortened'] = "bit.ly" in url or "tinyurl.com" in url or "ow.ly" in url #expanded shorteners list
        report['double_slash_redirect'] = "//" in url[8:] if len(url) > 8 else False #check for '//' after the initial 'https://' or 'http://'

        # 4. Content Analysis (Requires fetching the page)
        try:
            response = requests.get(url, timeout=5, verify=False)  # Set a timeout, disable SSL verification (use with caution!)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            soup = BeautifulSoup(response.content, "html.parser")

            report['title'] = soup.title.string if soup.title else None
            report['iframes'] = len(soup.find_all('iframe'))
            report['scripts'] = len(soup.find_all('script'))
            report['external_links'] = len([link.get('href') for link in soup.find_all('a') if link.get('href') and not link.get('href').startswith('#') and not parsed_url.netloc in link.get('href')])

            #Content Based Features
            report['https'] = parsed_url.scheme == "https"
            report['favicon'] = any(link.get('href') for link in soup.find_all('link', rel='icon'))
            report['login_form'] = bool(soup.find('form', {'action': re.compile(r'login|signin', re.IGNORECASE)}))


        except requests.exceptions.RequestException as e:
            report['content_error'] = str(e)
        except Exception as e:
            report['parsing_error'] = str(e)

        # 5. Advanced Phishing Features

        # a. URL Lexical Features
        report['url_length'] = len(url)
        report['shortening_service'] = "bit.ly" in url or "tinyurl.com" in url or "ow.ly" in url
        report['at_symbol'] = "@" in url
        report['double_slash_redirect'] = "//" in url[8:] if len(url) > 8 else False
        report['prefix_suffix_separation'] = "-" in parsed_url.netloc
        report['subdomain_count'] = parsed_url.netloc.count(".")

        # b. Domain-Based Features
        try:
            report['domain_age'] = (datetime.datetime.now() - report['whois']['creation_date'][0]).days if isinstance(report['whois']['creation_date'], list) else (datetime.datetime.now() - report['whois']['creation_date']).days if report['whois'] and report['whois']['creation_date'] else None
        except:
            report['domain_age'] = None

        try:
            ip_address = socket.gethostbyname(parsed_url.netloc)
            report['ip_address'] = ip_address
            try:
                ipaddress.ip_address(ip_address)
                report['ip_address_format'] = True
            except ValueError:
                report['ip_address_format'] = False
        except socket.gaierror:
            report['ip_address'] = "Could not resolve hostname"
            report['ip_address_format'] = False


        # d. DNS Records (Requires dnspython)
        try:
            resolver = dns.resolver.Resolver()
            a_records = resolver.resolve(parsed_url.netloc, 'A')
            report['dns_a_records'] = [record.address for record in a_records]
            mx_records= resolver.resolve(parsed_url.netloc, 'MX')
            report['dns_mx_records'] = [record.exchange.to_text() for record in mx_records]
            txt_records= resolver.resolve(parsed_url.netloc, 'TXT')
            report['dns_txt_records'] = [record.strings for record in txt_records]
        except dns.resolver.NXDOMAIN:
            report['dns_records_error'] = "Domain not found"
        except dns.exception.DNSException as e:
            report['dns_records_error'] = str(e)

        # 6. Phishing Heuristics (Updated)
        phishing_score = 0
        if report['length'] > 75: phishing_score += 1
        if report['shortening_service']: phishing_score += 2
        if report['at_symbol']: phishing_score += 2
        if report['double_slash_redirect']: phishing_score += 2
        if report['prefix_suffix_separation']: phishing_score += 1
        if report['subdomain_count'] > 3: phishing_score += 1
        if report.get('domain_age', 365) < 30: phishing_score += 2 #newly registered domains are suspicious
        if not report['https']: phishing_score += 2
        if not report['favicon']: phishing_score += 1
        if report['login_form']: phishing_score += 3
        if report.get('ip_address_format'): phishing_score += 2
        if 'whois_error' in report: phishing_score += 1
        if 'content_error' in report: phishing_score += 1
        if report.get('iframes',0)>2: phishing_score +=1
        if report.get('external_links',0)>10: phishing_score += 1
        if 'dns_records_error' in report: phishing_score += 1

        report['phishing_score'] = phishing_score

    except Exception as e:
        report['error'] = str(e)

    return report

# Example usage:
url_to_analyze = "http://google.com" # Replace with any URL
analysis_result = analyze_url(url_to_analyze)
import json
print(json.dumps(analysis_result, indent=4, default=str))

url_to_analyze = "https://www.wellsfarg0.com/"  # Example phishing URL
analysis_result = analyze_url(url_to_analyze)
print(json.dumps(analysis_result, indent=4, default=str))

url_to_analyze = "https://www.google.com"  # Example valid URL
analysis_result = analyze_url(url_to_analyze)
print(json.dumps(analysis_result, indent=4, default=str))

url_to_analyze = "https://www.facebook.com"  # Example valid URL
analysis_result = analyze_url(url_to_analyze)
print(json.dumps(analysis_result, indent=4, default=str))