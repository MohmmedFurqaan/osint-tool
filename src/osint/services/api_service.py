import httpx
import asyncio
import re

async def get_api_endpoints_async(domain: str, url: str) -> list:
    """
    Search for API endpoints using Wayback Machine, Robots.txt, and Path Probing.
    """
    endpoints = set()
    
    # Common paths to probe
    common_paths = [
        "/swagger.json",
        "/openapi.json",
        "/api/docs",
        "/graphql",
        "/api/v1/status",
        "/api/"
    ]
    
    if not url.startswith("http"):
        url = f"http://{url}"
        
    base_url = url.rstrip("/")
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        # 1. Path Probing
        async def probe_path(path):
            try:
                resp = await client.head(f"{base_url}{path}")
                if resp.status_code in [200, 401, 403]: # 401/403 means it exists but is protected
                    endpoints.add(f"{base_url}{path}")
            except Exception:
                pass
                
        # 2. Robots.txt parsing
        async def check_robots():
            try:
                resp = await client.get(f"{base_url}/robots.txt")
                if resp.status_code == 200:
                    lines = resp.text.split('\n')
                    for line in lines:
                        if line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if 'api' in path.lower() or 'graphql' in path.lower() or 'swagger' in path.lower():
                                endpoints.add(f"{base_url}{path} (Found in robots.txt)")
            except Exception:
                pass
                
        # 3. Wayback Machine Search
        async def check_wayback():
            try:
                cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*api*&output=json&limit=100&fl=original"
                resp = await client.get(cdx_url)
                if resp.status_code == 200:
                    data = resp.json()
                    # data[0] is ['original']
                    if len(data) > 1:
                        for entry in data[1:]:
                            endpoint = entry[0]
                            endpoints.add(f"{endpoint} (Wayback Machine)")
            except Exception:
                pass

        # Run all discovery tasks concurrently
        tasks = [probe_path(path) for path in common_paths]
        tasks.append(check_robots())
        tasks.append(check_wayback())
        
        await asyncio.gather(*tasks)
        
    return sorted(list(endpoints))
