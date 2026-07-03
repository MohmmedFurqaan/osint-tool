import httpx

async def get_wayback_async(domain: str) -> dict:
    """
    Fetch history info from Wayback Machine CDX API
    """
    try:
        # We query the CDX API to see how many captures and first/last date
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1: # data[0] is header ['timestamp']
                    first_seen = data[1][0]
                    return {
                        "first_seen": first_seen,
                        "archive_url": f"https://web.archive.org/web/*/{domain}"
                    }
    except Exception as e:
        return {"error": str(e)}
        
    return {}
