import validators
from urllib.parse import urlparse
from src.osint.models.target import Target

def validate_and_normalize(raw_url: str) -> Target:
    """
    Validates and normalizes the user-supplied raw URL.
    Returns a Target object or raises ValueError if invalid.
    """
    # Clean up common user typos
    url = raw_url.strip()
    if url.startswith("https:https:"):
        url = url.replace("https:https:", "https://")
    elif url.startswith("http:http:"):
        url = url.replace("http:http:", "http://")
        
    if url.startswith("https:") and not url.startswith("https://"):
        url = url.replace("https:", "https://", 1)
    elif url.startswith("http:") and not url.startswith("http://"):
        url = url.replace("http:", "http://", 1)
        
    if not url.startswith("http"):
        url = f"https://{url}"
        
    if not validators.url(url):
        raise ValueError(f"Invalid URL format: {raw_url}")
        
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    scheme = parsed.scheme if parsed.scheme else "N/A"
    
    return Target(
        raw_input=raw_url,
        domain=domain,
        scheme=scheme,
        url=url
    )
