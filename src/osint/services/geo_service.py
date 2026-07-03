import httpx

async def get_geo_async(domain_or_ip: str) -> dict:
    """
    Fetch IP Geolocation and ASN info from ip-api.com
    """
    try:
        url = f"http://ip-api.com/json/{domain_or_ip}?fields=status,message,country,city,isp,org,as,query"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
    except Exception as e:
        return {"error": str(e)}
        
    return {}
