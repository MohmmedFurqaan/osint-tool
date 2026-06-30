import asyncio
import os
import socket
import shodan

def _sync_get_shodan(domain: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"error": "No SHODAN_API_KEY found in environment"}
    
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

async def get_shodan_async(domain: str) -> dict:
    return await asyncio.to_thread(_sync_get_shodan, domain)
