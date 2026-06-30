import whois
import dns.resolver
import ssl
import socket
import requests
import datetime
import os
import shodan
import json
from dotenv import load_dotenv

load_dotenv()


def get_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        return {
            "registrar": w.registrar,
            "creation_date": str(creation),
            "expiration_date": str(expiration)
        }
    except Exception as e:
        return {"error": str(e)}

def get_dns(domain: str) -> dict:
    records = {}
    for record_type in ['A', 'MX', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
        except Exception:
            records[record_type] = []
    return records

def get_ssl(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return {
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "expires": cert.get('notAfter')
                }
    except Exception as e:
        return {"error": str(e)}

def get_headers(url: str) -> dict:
    try:
        if not url.startswith('http'):
            url = f"http://{url}"
        resp = requests.head(url, timeout=5, allow_redirects=True)
        return dict(resp.headers)
    except Exception as e:
        return {"error": str(e)}

def get_shodan(domain: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"error": "No SHODAN_API_KEY found in .env"}
    
    try:
        api = shodan.Shodan(api_key)
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {"error": f"Could not resolve domain {domain} to IP"}
            
        host_info = api.host(ip)
        return {
            "ip": ip,
            "os": host_info.get("os", "N/A"),
            "ports": host_info.get("ports", []),
            "hostnames": host_info.get("hostnames", []),
            "org": host_info.get("org", "N/A")
        }
    except shodan.APIError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

def generate_json(domain: str, data: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, mode='w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)
    return output_path
