import httpx

async def get_headers_async(url: str) -> dict:
    try:
        if not url.startswith('http'):
            url = f"http://{url}"
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.head(url)
            # httpx headers are case-insensitive dict-like, convert to normal dict
            return dict(resp.headers)
    except Exception as e:
        return {"error": str(e)}
