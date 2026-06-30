import asyncio
import whois

def _sync_get_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        return {
            "registrar": w.registrar,
            "creation_date": str(creation) if creation else None,
            "expiration_date": str(expiration) if expiration else None
        }
    except Exception as e:
        return {"error": str(e)}

async def get_whois_async(domain: str) -> dict:
    return await asyncio.to_thread(_sync_get_whois, domain)
