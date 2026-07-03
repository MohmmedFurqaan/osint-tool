import httpx
import re

async def get_subdomains_async(domain: str) -> list:
    """
    Fetch subdomains using Certificate Transparency logs from crt.sh
    """
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # name_value can contain multiple domains separated by newline
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        # Ignore wildcard and exactly matching domain
                        if not sub.startswith('*') and sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)
    except Exception:
        pass
        
    return sorted(list(subdomains))
