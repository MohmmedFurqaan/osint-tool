import asyncio
import dns.resolver
import dns.asyncresolver

async def get_dns_async(domain: str) -> dict:
    records = {}
    record_types = ['A', 'MX', 'TXT']
    
    resolver = dns.asyncresolver.Resolver()
    
    async def resolve_type(rtype: str):
        try:
            answers = await resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []

    tasks = [resolve_type(rtype) for rtype in record_types]
    await asyncio.gather(*tasks)
    
    return records
