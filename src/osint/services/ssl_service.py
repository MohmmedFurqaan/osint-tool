import asyncio
import ssl
import socket

def _sync_get_ssl(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"error": "No certificate presented"}
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return {
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "expires": cert.get('notAfter')
                }
    except Exception as e:
        return {"error": str(e)}

async def get_ssl_async(domain: str) -> dict:
    return await asyncio.to_thread(_sync_get_ssl, domain)
